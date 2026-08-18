"""Batch review handlers, validation, and finding integration."""

from __future__ import annotations

import hashlib
import re
from pathlib import Path
from typing import Any

from ..core import findings, hypotheses, ptt, state
from ..core.history import history_contains
from ..core.phases import requires_hypothesis
from ..core.skill_policy import skill_spec
from ..core.skill_receipts import (
    HermesSkillViewAdapter,
    complete_delivery,
    get_binding,
    prepare_delivery,
)
from . import ptt_handlers
from .base import (
    _eng_path,
    _json,
    _running_background_command,
    _serialize_errors,
)
from .ptt_gates import (
    _redact_sensitive_note,
    _validate_phase_exit,
    _with_skill_token,
)


def _task_row_contains(path: Path, task_id: str, marker: str) -> bool:
    for line in path.read_text(encoding="utf-8").splitlines():
        match = re.match(r"^\|\s*(PT-[\w-]+)\s*\|", line.strip())
        if match and match.group(1) == task_id:
            return marker in line
    return False


def _validate_review_identity(
    args: dict[str, Any], pending: dict[str, Any]
) -> tuple[str, str, str, str, str, str]:
    """Extract and validate core identity fields from a review request."""
    eng_dir = str(args.get("eng_dir") or "")
    task_id = str(args.get("id") or "").strip()
    note = _redact_sensitive_note(str(args.get("note") or "").strip())
    status = str(args.get("status") or "[~]").strip()
    if not task_id or not note:
        raise ValueError("active task id and non-empty review note are required")
    if status not in {"[~]", "[x]", "[!]", "[-]"}:
        raise ValueError("status must be one of [~], [x], [!], or [-]")

    batch_id = str(pending.get("batch_id") or "").strip()
    captured_task = str(pending.get("ptt_task_id") or "").strip()
    if not batch_id or not captured_task:
        raise ValueError("pending batch is missing its batch or PTT task identity")
    if task_id != captured_task:
        raise ValueError(f"reviewed task {task_id!r} does not match batch task {captured_task!r}")
    return eng_dir, task_id, note, status, batch_id, captured_task


def _validate_review_ptt_state(
    eng_dir: str,
    task_id: str,
    status: str,
    batch_id: str,
    pending: dict[str, Any],
) -> tuple[Path, str, bool]:
    """Verify the PTT is in a valid state for batch review."""
    ptt_path = _eng_path(eng_dir) / "state" / "ptt.md"
    tasks = ptt.parse_ptt(ptt_path)
    selected = next((item for item in tasks if item.id == task_id), None)
    if selected is None:
        raise ValueError(f"batch task {task_id!r} is missing from the PTT")
    marker = f"[reviewed-batch:{batch_id}]"
    already_recorded = selected.status == status and _task_row_contains(ptt_path, task_id, marker)
    if not already_recorded:
        validation = ptt.validate_ptt(tasks)
        if validation.errors:
            raise ValueError("PTT must have exactly one valid active task before batch review")
        active = ptt.find_active_task(tasks)
        if not active or active.id != task_id:
            raise ValueError(f"batch task {task_id!r} must be the sole active [~] task")
        phases = {
            str(item.get("phase") or pending.get("phase") or "")
            for item in pending.get("commands") or []
        } - {""}
        incompatible = sorted(
            phase for phase in phases if not ptt.task_matches_phase(active, phase)
        )
        if incompatible:
            raise ValueError(
                f"batch task {task_id!r} is not phase-compatible with " + ", ".join(incompatible)
            )
    return ptt_path, marker, already_recorded


def _validate_review_history(eng_dir: str, pending: dict[str, Any]) -> None:
    """Ensure every pending command has been recorded in the execution history."""
    for item in pending.get("commands") or []:
        command = str(item.get("command") or "") if isinstance(item, dict) else str(item or "")
        if command and not history_contains(eng_dir, command):
            if _running_background_command(eng_dir, command):
                continue
            raise ValueError(
                f"pending command not yet in exact history: {command!r}; "
                "wait for execution completion before review"
            )


def _validate_review_finding(eng_dir: str, pending: dict[str, Any], finding: Any) -> None:
    """Validate an optional finding payload against the pending batch."""
    if finding is None:
        return
    if not isinstance(finding, dict):
        raise ValueError("finding must be an object when supplied")
    findings._validate_from_pending_batch(
        eng_dir,
        pending,
        title=str(finding.get("title") or ""),
        severity=str(finding.get("severity") or ""),
        description=str(finding.get("description") or ""),
        impact=str(finding.get("impact") or ""),
        remediation=str(finding.get("remediation") or ""),
        finding_id=str(finding.get("finding_id") or ""),
        hypothesis_id=str(finding.get("hypothesis_id") or ""),
    )


def _validate_review_batch(args: dict[str, Any], pending: dict[str, Any]) -> dict[str, Any]:
    """Validate all preconditions for a batch review."""
    eng_dir, task_id, note, status, batch_id, _ = _validate_review_identity(args, pending)
    ptt_path, marker, already_recorded = _validate_review_ptt_state(
        eng_dir, task_id, status, batch_id, pending
    )
    _validate_review_history(eng_dir, pending)
    _validate_review_finding(eng_dir, pending, args.get("finding"))
    return {
        "batch_id": batch_id,
        "task_id": task_id,
        "status": status,
        "note": note,
        "marker": marker,
        "already_recorded": already_recorded,
        "ptt_path": ptt_path,
        "finding": args.get("finding"),
    }


def _handle_review_batch_skill_reservation(
    engagement: Path,
    pending: dict[str, Any],
    args: dict[str, Any],
    skill: str,
) -> tuple[dict[str, Any], str | None]:
    """Handle an optional explicit review-skill reservation."""
    tasks = ptt.parse_ptt(engagement / "state" / "ptt.md")
    task_id = str(args.get("id") or "").strip()
    task = next((item for item in tasks if item.id == task_id), None)
    if task is None:
        raise ValueError(f"batch task {task_id!r} is missing from the PTT")
    hypothesis_id = str(args.get("hypothesis_id") or "").strip()
    phase = ptt.normalize_phase(task.phase)
    if requires_hypothesis(phase) and not hypothesis_id:
        raise ValueError(f"hypothesis_id is required for {phase.value} batch review")
    digest = "sha256:" + hashlib.sha256(f"policy:{skill}".encode()).hexdigest()
    reservation = prepare_delivery(
        engagement,
        session_id=state.resolve_session_id(engagement) or "review",
        skill=skill,
        bundle_digest=digest,
        phase="RETROSPECTIVE" if skill == "fp-check" else phase.value,
    )
    if reservation.owner:
        adapter_cls = getattr(ptt_handlers, "HermesSkillViewAdapter", HermesSkillViewAdapter)
        viewed = adapter_cls().view(skill, task_id=task_id)
        completed = complete_delivery(engagement, reservation, viewed)
        spec = skill_spec(skill)
        return args, _json(
            "skill_prepared" if completed.status == "delivered" else "skill_unavailable",
            transition_applied=False,
            released=False,
            skill={
                "name": skill,
                "digest": digest,
                "content": viewed.content,
                "error": viewed.error,
                "delivery_id": reservation.id,
                "source": spec.source if spec else None,
                "install_hint": spec.install_hint if spec else None,
                "trust": spec.trust if spec else None,
            },
        )
    if reservation.status == "preparing":
        return args, _json("skill_preparing", transition_applied=False, released=False)
    updated_args = {**args, "note": _with_skill_token(str(args.get("note") or ""), skill, digest)}
    return updated_args, None


def _execute_batch_review(
    engagement: Path,
    pending: dict[str, Any],
    args: dict[str, Any],
    skill: str,
) -> str:
    """Validate and execute the core batch review transition."""
    context = _validate_review_batch(args, pending)
    _validate_phase_exit(engagement, context["task_id"], context["status"])
    finding_result = None
    finding = context["finding"]
    if finding is not None:
        finding_result = findings._create_from_pending_batch(
            engagement,
            pending=pending,
            title=str(finding.get("title") or ""),
            severity=str(finding.get("severity") or ""),
            description=str(finding.get("description") or ""),
            impact=str(finding.get("impact") or ""),
            remediation=str(finding.get("remediation") or ""),
            finding_id=str(finding.get("finding_id") or ""),
            hypothesis_id=str(finding.get("hypothesis_id") or ""),
        )
        hypothesis_id = str(finding.get("hypothesis_id") or "").upper().removeprefix("H-")
        existing = next(
            (
                item
                for item in hypotheses.parse_hypotheses(engagement / "hypotheses.md")
                if item.id.lstrip("0") == (hypothesis_id.lstrip("0") or "0")
            ),
            None,
        )
        if existing is not None:
            linked = [
                value.strip() for value in existing.linked_findings.split(",") if value.strip()
            ]
            if finding_result["finding_id"] not in linked:
                linked.append(finding_result["finding_id"])
            hypotheses.update_hypothesis(
                engagement / "hypotheses.md",
                id=existing.id,
                linked_findings=", ".join(linked),
            )
    if not context["already_recorded"]:
        review_note = f"{context['note']} {context['marker']}"
        ptt.update_task(context["ptt_path"], context["task_id"], context["status"], review_note)
    batch_evidence = findings._batch_evidence(engagement, pending)
    supplied_evidence = [str(item) for item in (args.get("evidence_paths") or [])]
    evidence_paths = sorted(set(supplied_evidence) | set(batch_evidence))
    semantic = state.record_semantic_review(
        engagement,
        task_id=context["task_id"],
        hypothesis_id=str(args.get("hypothesis_id") or ""),
        skill=skill or "review",
        technique=str(args.get("technique") or "batch-review"),
        outcome=str(args.get("outcome") or "progress"),
        evidence_paths=evidence_paths,
        next_action=str(args.get("next_action") or "review evidence"),
        next_technique=str(args.get("next_technique") or ""),
        research_attempted=bool(args.get("research_attempted")),
    )
    state.clear_pending_sync(engagement)
    return _json(
        "ok",
        batch_id=context["batch_id"],
        task_id=context["task_id"],
        task_status=context["status"],
        released=True,
        finding=finding_result,
        finding_path=finding_result.get("path") if finding_result else None,
        binding_task_id=None,
        semantic_progress=semantic,
    )


@_serialize_errors
def handle_review_batch(args: dict[str, Any], **kwargs: Any) -> str:
    """Review one completed batch, optionally record a finding, and release its lock."""
    eng_dir = str(args.get("eng_dir") or "").strip()
    if not eng_dir:
        raise ValueError("eng_dir is required")
    engagement = _eng_path(eng_dir)
    review_lock = engagement / "state" / "review-batch.json"
    try:
        with state.workflow_lock(engagement), state.lock_file(review_lock):
            pending = state.get_pending_sync(engagement)
            if not pending:
                return _json(
                    "ok",
                    batch_id=None,
                    task_id=None,
                    task_status=None,
                    released=True,
                    finding=None,
                    finding_path=None,
                    message="nothing pending",
                )
            task_id = str(pending.get("ptt_task_id") or "").strip()
            binding = get_binding(engagement, task_id) if task_id else None
            if not binding:
                raise ValueError(
                    "the pending batch has no active delivered skill binding; "
                    "rebind or prepare the active PTT task before review"
                )
            skill = str(args.get("skill") or "").strip()
            binding_skill = str(binding.get("skill") or "")
            if skill and skill != "fp-check" and skill != binding_skill:
                # The delivered skill binding is the task-specific source of truth and
                # always wins over an explicitly passed skill (which may be the phase
                # default, e.g. 'pentest'). Don't hard-reject into a deadlock — bind to
                # the binding skill and hint at the resolution.
                skill = ""
            review_skill = skill or binding_skill
            args = {
                **args,
                "skill": review_skill,
                "hypothesis_id": str(
                    args.get("hypothesis_id") or binding.get("hypothesis_id") or ""
                ),
                "technique": str(
                    args.get("technique") or binding.get("technique") or "batch-review"
                ),
            }
            if skill:
                args, early_response = _handle_review_batch_skill_reservation(
                    engagement, pending, args, review_skill
                )
                if early_response is not None:
                    return early_response
            return _execute_batch_review(engagement, pending, args, review_skill)
    except (OSError, ValueError) as exc:
        return _json(
            "blocked",
            released=False,
            error=str(exc),
            next_action="Resolve the reported batch, PTT, history, or finding issue and retry violin_review_batch",
        )


__all__ = [
    "_execute_batch_review",
    "_handle_review_batch_skill_reservation",
    "_validate_review_batch",
    "_validate_review_finding",
    "_validate_review_history",
    "_validate_review_identity",
    "_validate_review_ptt_state",
    "handle_review_batch",
]
