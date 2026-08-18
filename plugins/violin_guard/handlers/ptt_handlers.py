"""PTT workflow, task lifecycle transition handlers, and facade re-exports."""

from __future__ import annotations

import hashlib
import re
from pathlib import Path
from typing import Any

from ..core import hypotheses, ptt, state
from ..core.phases import requires_hypothesis
from ..core.skill_policy import skill_spec
from ..core.skill_receipts import (
    HermesSkillViewAdapter,
    bind_task,
    complete_delivery,
    prepare_delivery,
)
from .base import (
    _eng_path,
    _json,
    _serialize_errors,
)
from .ptt_gates import (
    _find_unlinked_validated_hypotheses,
    _redact_sensitive_note,
    _validate_disposition_entry,
    _validate_methodology_gates,
    _validate_phase_exit,
    _with_skill_token,
)
from .ptt_rebind import (
    _rebind_fields,
    _validate_pending_history,
    _validate_pending_identity,
    _validated_replacement_task,
    handle_rebind_pending_batch,
)
from .ptt_review import (
    _execute_batch_review,
    _handle_review_batch_skill_reservation,
    _validate_review_batch,
    _validate_review_finding,
    _validate_review_history,
    _validate_review_identity,
    _validate_review_ptt_state,
    handle_review_batch,
)


def _start_ptt_task(
    ptt_path: Path,
    tasks: list[ptt.PttTask],
    task_id: str,
    status: str,
    note: str,
    eng_dir: str | Path | None = None,
) -> str:
    """Arm one untouched, phase-bound task before the first target command."""
    if status != "[~]":
        raise ValueError(
            f"invalid status {status!r}; starting a task via violin_record_ptt requires status='[~]' "
            "(use bracket tokens '[~]', '[x]', '[-]', '[!]', not English status words like 'in_progress')"
        )
    note = _redact_sensitive_note(note)
    selected = next((item for item in tasks if item.id == task_id), None)
    if selected is None:
        raise ValueError(f"PTT task {task_id!r} not found")
    if selected.status not in {"[ ]", "[~]"}:
        raise ValueError(f"PTT task {task_id!r} must be [ ] or [~] before it can be started")
    try:
        phase = ptt.normalize_phase(selected.phase)
    except ValueError as exc:
        raise ValueError(f"PTT task {task_id!r} must sit below a valid Phase heading") from exc

    active = ptt.find_active_task(tasks)
    updates = {task_id: (status, note)}
    if active and active.id != task_id:
        resolved_dir = ptt_path.parent.parent if eng_dir is None else Path(eng_dir)
        if state.has_pending_sync(resolved_dir):
            raise ValueError("an active PTT task already exists; review its pending batch first")
        _validate_phase_exit(resolved_dir, active.id, "[x]")
        superseded_note = f"{active.note} [superseded-by:{task_id}]".strip()
        updates[active.id] = ("[x]", superseded_note)
    ptt.update_tasks(ptt_path, updates)
    return _json("ok", task_id=task_id, phase=phase.value, task_started=True)


def _task_row_contains(path: Path, task_id: str, marker: str) -> bool:
    for line in path.read_text(encoding="utf-8").splitlines():
        match = re.match(r"^\|\s*(PT-[\w-]+)\s*\|", line.strip())
        if match and match.group(1) == task_id:
            return marker in line
    return False


def _validate_record_ptt_inputs(
    args: dict[str, Any], doc: list[ptt.PttTask], pending: dict[str, Any] | None
):
    """Validate preconditions and return normalized phase and hypothesis details."""
    task = args.get("id")
    note = (args.get("note") or "").strip()
    skill = str(args.get("skill") or "").strip()
    technique = str(args.get("technique") or "").strip()

    if not task or not note:
        raise ValueError(
            "task id and non-empty lifecycle note required; use id=PT-XXX, status='[~]', "
            "skill=<routed skill>, technique=<concrete technique>, and note=<what changed>"
        )
    if not skill or not technique:
        raise ValueError(
            "skill and technique are required before a PTT update; provide the active routed "
            "skill and a concrete technique (for example technique='route-enumeration')"
        )
    if pending:
        raise ValueError(
            "a target batch is pending; use violin_review_batch instead of violin_record_ptt"
        )
    selected = next((item for item in doc if item.id == task), None)
    selected_phase = selected.phase if selected else str(args.get("phase") or "RECON")
    try:
        phase = ptt.normalize_phase(selected_phase)
    except ValueError as exc:
        raise ValueError(f"PTT task {task!r} must sit below a valid Phase heading") from exc
    hypothesis_id = str(args.get("hypothesis_id") or "").strip()
    if requires_hypothesis(phase) and not hypothesis_id:
        raise ValueError(
            f"hypothesis_id is required for {phase.value} PTT work; create or select a canonical "
            "H-XXX hypothesis first and pass hypothesis_id='H-XXX'"
        )

    vulnerability_class = ""
    candidate_source = ""
    if hypothesis_id:
        normalized = hypothesis_id.removeprefix("H-").lstrip("0") or "0"
        matched = next(
            (
                hyp
                for hyp in hypotheses.parse_hypotheses(_eng_path(args["eng_dir"]) / "hypotheses.md")
                if hyp.id.lstrip("0") == normalized
            ),
            None,
        )
        vulnerability_class = matched.vuln_class if matched else ""
        candidate_source = matched.candidate_source if matched else ""

    return task, note, skill, technique, phase, hypothesis_id, vulnerability_class, candidate_source


def _prepare_record_ptt_delivery(
    eng_dir: str,
    task: str,
    skill: str,
    phase: ptt.Phase,
    vulnerability_class: str,
    candidate_source: str,
):
    """Prepare skill delivery reservation and return (reservation, digest, early_response_or_None)."""
    digest = "sha256:" + hashlib.sha256(f"policy:{skill}".encode()).hexdigest()
    reservation = prepare_delivery(
        eng_dir,
        session_id=state.resolve_session_id(eng_dir) or "ptt",
        skill=skill,
        bundle_digest=digest,
        phase=phase.value,
        vulnerability_class=vulnerability_class or None,
        candidate_source=candidate_source or None,
    )
    if reservation.owner:
        viewed = HermesSkillViewAdapter().view(skill, task_id=task)
        completed = complete_delivery(eng_dir, reservation, viewed)
        spec = skill_spec(skill)
        early_resp = _json(
            "skill_prepared" if completed.status == "delivered" else "skill_unavailable",
            transition_applied=False,
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
        return reservation, digest, early_resp
    if reservation.status == "preparing":
        early_resp = _json(
            "skill_preparing", transition_applied=False, skill={"name": skill, "digest": digest}
        )
        return reservation, digest, early_resp
    return reservation, digest, None


def _apply_ptt_task_transition(
    eng_dir: str,
    doc: list[ptt.PttTask],
    task: str,
    status: str,
    note: str,
    binding: dict[str, Any],
    title: str | None = None,
    raw_phase: str | None = None,
) -> str:
    """Apply PTT state mutations and return final JSON response."""
    note = _redact_sensitive_note(note)
    ptt_file = _eng_path(eng_dir) / "state" / "ptt.md"
    if not any(item.id == task for item in doc):
        created = ptt.create_task(
            ptt_file,
            task,
            title or task,
            raw_phase or "RECON",
            note,
        )
        doc = ptt.parse_ptt(ptt_file)
        if status == "[ ]":
            return _json("ok", task_id=created.id, task_created=True)
    existing = next((item for item in doc if item.id == task), None)
    if existing and existing.status == "[~]" and status == "[~]":
        active = ptt.find_active_task(doc)
        if active and active.id != task:
            resolved_dir = _eng_path(eng_dir)
            if state.has_pending_sync(resolved_dir):
                raise ValueError(
                    "an active PTT task already exists; review its pending batch first"
                )
            _validate_phase_exit(resolved_dir, active.id, "[x]")
            superseded_note = f"{active.note} [superseded-by:{task}]".strip()
            ptt.update_task(ptt_file, active.id, "[x]", superseded_note)
        ptt.update_task(ptt_file, task, "[~]", note)
        return _json("ok", task_id=task, task_refreshed=True, binding=binding)
    if existing and status in {"[x]", "[-]"}:
        if existing.status != "[~]":
            raise ValueError("only the active [~] task may be closed outside a batch")
        _validate_phase_exit(_eng_path(eng_dir), task, status)
        ptt.update_task(ptt_file, task, status, note)
        return _json("ok", task_id=task, task_closed=True)
    return _start_ptt_task(ptt_file, doc, task, status, note, eng_dir=eng_dir)


@_serialize_errors
def handle_record_ptt(args: dict[str, Any], **kwargs: Any) -> str:
    eng_dir = args["eng_dir"]
    doc = ptt.parse_ptt(_eng_path(eng_dir) / "state" / "ptt.md")
    pending = state.get_pending_sync(eng_dir)
    status = (args.get("status") or "[~]").strip() or "[~]"

    (
        task,
        note,
        skill,
        technique,
        phase,
        hypothesis_id,
        vuln_class,
        cand_source,
    ) = _validate_record_ptt_inputs(args, doc, pending)

    reservation, digest, early_response = _prepare_record_ptt_delivery(
        eng_dir, task, skill, phase, vuln_class, cand_source
    )
    if early_response is not None:
        return early_response

    with state.workflow_lock(eng_dir):
        doc = ptt.parse_ptt(_eng_path(eng_dir) / "state" / "ptt.md")
        pending = state.get_pending_sync(eng_dir)
        _validate_record_ptt_inputs(args, doc, pending)
        binding = bind_task(
            eng_dir,
            task_id=task,
            delivery_id=reservation.id,
            hypothesis_id=hypothesis_id,
            technique=technique,
        )
        note = _with_skill_token(note, skill, digest)
        return _apply_ptt_task_transition(
            eng_dir,
            doc,
            task,
            status,
            note,
            binding,
            title=args.get("title"),
            raw_phase=args.get("phase"),
        )


__all__ = [
    "_apply_ptt_task_transition",
    "_execute_batch_review",
    "_find_unlinked_validated_hypotheses",
    "_handle_review_batch_skill_reservation",
    "_prepare_record_ptt_delivery",
    "_rebind_fields",
    "_redact_sensitive_note",
    "_start_ptt_task",
    "_task_row_contains",
    "_validate_disposition_entry",
    "_validate_methodology_gates",
    "_validate_pending_history",
    "_validate_pending_identity",
    "_validate_phase_exit",
    "_validate_record_ptt_inputs",
    "_validate_review_batch",
    "_validate_review_finding",
    "_validate_review_history",
    "_validate_review_identity",
    "_validate_review_ptt_state",
    "_validated_replacement_task",
    "_with_skill_token",
    "handle_rebind_pending_batch",
    "handle_record_ptt",
    "handle_review_batch",
]
