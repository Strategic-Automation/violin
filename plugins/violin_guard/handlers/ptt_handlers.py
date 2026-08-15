"""PTT workflow and batch review handlers."""

from __future__ import annotations

import hashlib
import re
import sys
from pathlib import Path

import yaml

from .. import findings, hypotheses, ptt, state
from ..history import history_contains
from ..phases import requires_hypothesis
from ..skill_policy import skill_spec
from ..skill_receipts import (
    HermesSkillViewAdapter,
    bind_task,
    complete_delivery,
    get_binding,
    prepare_delivery,
)
from .base import (
    _eng_path,
    _json,
    _running_background_command,
    _serialise_errors,
)

_JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b")
_BEARER_RE = re.compile(r"(?i)(\bBearer\s+)[A-Za-z0-9._~+/=-]+")
_OPENROUTER_KEY_RE = re.compile(r"\bsk-or-v1-[A-Za-z0-9]+\b")


def _redact_sensitive_note(note: str) -> str:
    """Prevent credentials and bearer tokens from entering PTT state notes."""
    redacted = _JWT_RE.sub("[REDACTED_JWT]", note)
    redacted = _BEARER_RE.sub(r"\1[REDACTED_TOKEN]", redacted)
    return _OPENROUTER_KEY_RE.sub("[REDACTED_API_KEY]", redacted)


def _with_skill_token(note: str, skill: str, digest: str) -> str:
    """Keep exactly one replaceable selection token in a PTT note."""
    token = f"[skill:{skill}@{digest}]"
    stripped = re.sub(r"\s*\[skill:[^\]]+\]", "", note).strip()
    return f"{stripped} {token}".strip()


def _validate_phase_exit(engagement: Path, task_id: str, status: str) -> None:
    """Block phase completion while required evidence or dispositions are incomplete."""
    if status != "[x]":
        return
    task = next(
        (item for item in ptt.parse_ptt(engagement / "state" / "ptt.md") if item.id == task_id),
        None,
    )
    if task is None:
        raise ValueError(f"PTT task {task_id!r} is missing")
    phase = ptt.normalize_phase(task.phase)
    board = hypotheses.parse_hypotheses(engagement / "hypotheses.md")
    if phase.value == "VULN_RESEARCH":
        scope_path = engagement / "scope" / "scope.yaml"
        scope_data = (
            yaml.safe_load(scope_path.read_text(encoding="utf-8")) if scope_path.is_file() else {}
        )
        if isinstance(scope_data, dict) and (
            (scope_data.get("engagement") or {}).get("audit_mode") is True
        ):
            matrix_path = engagement / "state" / "coverage-matrix.yaml"
            if not matrix_path.is_file():
                raise ValueError(
                    "VULN_RESEARCH cannot close until state/coverage-matrix.yaml exists"
                )
            matrix = yaml.safe_load(matrix_path.read_text(encoding="utf-8"))
            entries = matrix.get("coverage") if isinstance(matrix, dict) else None
            if not isinstance(entries, dict) or not entries:
                raise ValueError("coverage matrix must contain a non-empty coverage mapping")
            obligations = (scope_data.get("engagement") or {}).get("coverage_obligations") or []
            cell_texts = [
                f"{str(name).lower()} {str(entry.get('evidence_or_reason') or '').lower()}"
                for name, entry in entries.items()
                if isinstance(entry, dict)
            ]
            unresolved_coverage = []
            # Client-provided in-scope endpoints must map to a matrix cell.
            # Route-level obligations keep the agent honest about coverage
            # without leaking what is vulnerable — the same requirement a
            # strict client engagement would hold it to.
            for obligation in obligations:
                obligation = str(obligation).strip().lower()
                if not obligation:
                    continue
                if not any(obligation in text for text in cell_texts):
                    unresolved_coverage.append(f"{obligation} (no coverage-matrix cell)")
            for name, entry in entries.items():
                if not isinstance(entry, dict):
                    unresolved_coverage.append(name)
                    continue
                status = str(entry.get("status") or "").strip().lower()
                reason = str(entry.get("evidence_or_reason") or "").strip()
                if status not in {"tested", "not_applicable", "blocked"} or not reason:
                    unresolved_coverage.append(name)
                    continue
                # not_applicable must be backed by an evidence file: a bare
                # reason ("no rate-limit behavior observed") is a memory
                # reconstruction, the exact false-positive factory. Self-
                # declaring N/A against a live endpoint without probing it is
                # how real findings are missed. blocked must name the guard
                # that prevented testing.
                if status == "not_applicable" and "evidence/" not in reason:
                    unresolved_coverage.append(f"{name} (not_applicable without evidence file)")
                elif status == "blocked" and "guard" not in reason.lower():
                    unresolved_coverage.append(f"{name} (blocked without guard reference)")
                # tested must cite a canonical artifact (evidence path, FIND,
                # or hypothesis id) — a bare narrative ("no open redirect
                # parameter found") is aspirational coverage, not proof.
                elif status == "tested" and not re.search(
                    r"evidence/|FIND-\d+|H-\d+", reason, re.IGNORECASE
                ):
                    unresolved_coverage.append(
                        f"{name} (tested without evidence/FIND/hypothesis reference)"
                    )
            if unresolved_coverage:
                hints = [
                    "how to fix: each obligation must map to a coverage-matrix cell",
                    "  - 'tested' cells: evidence_or_reason must cite evidence/, FIND-NNN, or a hypothesis id",
                    "  - 'not_applicable' cells: evidence_or_reason must cite an evidence/ file showing the probe",
                    "    (run the probe, save its output under evidence/vuln-research/, then reference that path)",
                    "  - 'blocked' cells: evidence_or_reason must name the guard that prevented testing",
                    "  - missing cells: add a cell for the route and disposition it as above",
                ]
                raise ValueError(
                    "VULN_RESEARCH cannot close with undispositioned coverage: "
                    + ", ".join(unresolved_coverage)
                    + ". "
                    + " ".join(hints)
                )
        unresolved = [
            f"H-{item.id}" for item in board if item.canonical_status() in {"Candidate", "Likely"}
        ]
        # A Rejected hypothesis disposed as not_implemented must still carry a
        # real executed test and evidence. "N/A - placeholder" with no evidence
        # means the cheapest discriminating test never ran — the agent disposed
        # it from the conversation (e.g. rejecting a default-credential login
        # check this way while the endpoint was never probed). Surface-mapping
        # hypotheses (e.g. "API surface enumeration") pass when they cite real
        # bundle/probe evidence.
        if not unresolved:
            untested_disposals = []
            for item in board:
                if item.canonical_status() != "Rejected":
                    continue
                if item.verification_status.strip().lower() != "not_implemented":
                    continue
                cmd = item.test_command.strip().lower()
                evidence_cited = bool((item.runtime_evidence or item.evidence or "").strip())
                if (
                    cmd in {"", "n/a", "na", "none", "-"}
                    or cmd.startswith("n/a")
                    or not evidence_cited
                ):
                    untested_disposals.append(
                        f"H-{item.id} (cheapest test: {(item.cheapest_test or '?').strip()!r})"
                    )
            if untested_disposals:
                raise ValueError(
                    "VULN_RESEARCH cannot close with rejections that never ran their "
                    "cheapest discriminating test: "
                    + ", ".join(untested_disposals)
                    + ". Execute the test and record Test Command/Test Response/Runtime "
                    "Evidence (or keep the hypothesis active) before closing."
                )
        if unresolved:
            raise ValueError(
                "VULN_RESEARCH cannot close with unresolved hypotheses: " + ", ".join(unresolved)
            )
        # Canonization gate: a Validated hypothesis without a linked FIND file
        # is invisible to downstream reporting/validation — evidence exists but
        # no written claim ties it to a canonical finding, so the finding is
        # lost at closeout. Require 1:N links now, at phase close, not at
        # REPORTING (closeout skips REPORTING tasks).
        uncanonized = []
        for item in board:
            if item.canonical_status() != "Validated":
                continue
            linked = [
                value.strip().upper()
                for value in str(item.linked_findings or "").split(",")
                if value.strip()
            ]
            if not linked or not any(
                (engagement / "evidence" / "findings" / f"{fid}.md").is_file() for fid in linked
            ):
                uncanonized.append(f"H-{item.id}")
        if uncanonized:
            raise ValueError(
                "VULN_RESEARCH cannot close until every Validated hypothesis links a "
                "canonical evidence/findings/FIND-NNN.md file (1:N allowed): "
                + ", ".join(uncanonized)
                + ". Update Linked findings on the hypothesis board via "
                "violin_record_hypothesis before closing."
            )
    if phase.value == "REPORTING":
        scope_path = engagement / "scope" / "scope.yaml"
        scope_data = (
            yaml.safe_load(scope_path.read_text(encoding="utf-8")) if scope_path.is_file() else {}
        )
        # Audit mode: REPORTING may not close unless the engagement actually
        # reached EXPLOITATION or later. A run that logs everything as recon,
        # declares coverage finalized, and jumps straight to REPORTING has
        # skipped the entire validation phase. The agent cannot fake this:
        # evidence only accumulates by running commands in a later phase.
        if isinstance(scope_data, dict) and (
            (scope_data.get("engagement") or {}).get("audit_mode") is True
        ):
            history_path = engagement / "state" / "history.md"
            reached_later_phase = False
            if history_path.is_file():
                history_text = history_path.read_text(encoding="utf-8", errors="replace")
                for token in re.findall(r"phase=([a-zA-Z_]+)", history_text):
                    if token.lower() in {"exploitation", "post_exploitation", "privesc", "flags"}:
                        reached_later_phase = True
                        break
            if not reached_later_phase:
                raise ValueError(
                    "REPORTING cannot close: no commands were executed in EXPLOITATION or a "
                    "later phase (all history is phase=recon). Activate PT-103 and run "
                    "proof-verification commands under phase=exploitation before reporting; "
                    "skipping the exploitation phase produces an incomplete assessment."
                )
        missing: list[str] = []
        for item in board:
            if item.canonical_status() != "Validated":
                continue
            finding_ids = [
                value.strip().upper()
                for value in str(item.linked_findings or "").split(",")
                if value.strip()
            ]
            if not any(
                (engagement / "evidence" / "findings" / f"{fid}.md").is_file()
                for fid in finding_ids
            ):
                missing.append(f"H-{item.id}")
        if missing:
            raise ValueError(
                "REPORTING cannot close until Validated hypotheses link canonical findings: "
                + ", ".join(missing)
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


def _validate_review_identity(a: dict, pending: dict) -> tuple[str, str, str, str, str, str]:
    """Extract and validate core identity fields from a review request.

    Returns (eng_dir, task_id, note, status, batch_id, captured_task).
    """
    eng_dir = str(a.get("eng_dir") or "")
    task_id = str(a.get("id") or "").strip()
    note = _redact_sensitive_note(str(a.get("note") or "").strip())
    status = str(a.get("status") or "[~]").strip()
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
    eng_dir: str, task_id: str, status: str, batch_id: str, pending: dict
) -> tuple[Path, str, bool]:
    """Verify the PTT is in a valid state for batch review.

    Returns (ptt_path, marker, already_recorded).
    """
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


def _validate_review_history(eng_dir: str, pending: dict) -> None:
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


def _validate_review_finding(eng_dir: str, pending: dict, finding) -> None:
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


def _validate_review_batch(a: dict, pending: dict) -> dict:
    """Validate all preconditions for a batch review.

    Delegates to focused sub-validators for identity, PTT state, command
    history, and optional finding validation.
    """
    eng_dir, task_id, note, status, batch_id, _ = _validate_review_identity(a, pending)
    ptt_path, marker, already_recorded = _validate_review_ptt_state(
        eng_dir, task_id, status, batch_id, pending
    )
    _validate_review_history(eng_dir, pending)
    _validate_review_finding(eng_dir, pending, a.get("finding"))
    return {
        "batch_id": batch_id,
        "task_id": task_id,
        "status": status,
        "note": note,
        "marker": marker,
        "already_recorded": already_recorded,
        "ptt_path": ptt_path,
        "finding": a.get("finding"),
    }


def _get_skill_view_adapter():
    for _name, mod in list(sys.modules.items()):
        if mod and hasattr(mod, "HermesSkillViewAdapter"):
            cls = mod.HermesSkillViewAdapter
            if getattr(cls, "__module__", "") not in (
                "plugins.violin_guard.skill_receipts",
                "vgpkg.skill_receipts",
            ):
                return cls
    return HermesSkillViewAdapter


def _validate_record_ptt_inputs(a: dict, doc: list, pending: dict | None):
    """Validate preconditions and return normalized phase and hypothesis details."""
    task = a.get("id")
    note = (a.get("note") or "").strip()
    skill = str(a.get("skill") or "").strip()
    technique = str(a.get("technique") or "").strip()

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
    selected_phase = selected.phase if selected else str(a.get("phase") or "RECON")
    try:
        phase = ptt.normalize_phase(selected_phase)
    except ValueError as exc:
        raise ValueError(f"PTT task {task!r} must sit below a valid Phase heading") from exc
    hypothesis_id = str(a.get("hypothesis_id") or "").strip()
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
                h
                for h in hypotheses.parse_hypotheses(_eng_path(a["eng_dir"]) / "hypotheses.md")
                if h.id.lstrip("0") == normalized
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
    """Prepare skill delivery reservation and return (reservation, early_response_or_None)."""
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
        adapter_cls = _get_skill_view_adapter()
        viewed = adapter_cls().view(skill, task_id=task)
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
    doc: list,
    task: str,
    status: str,
    note: str,
    binding: dict,
    title: str | None = None,
    raw_phase: str | None = None,
):
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


@_serialise_errors
def handle_record_ptt(a, **kwargs):
    eng_dir = a["eng_dir"]
    doc = ptt.parse_ptt(_eng_path(eng_dir) / "state" / "ptt.md")
    pending = state.get_pending_sync(eng_dir)
    status = a.get("status", "[~]")

    (
        task,
        note,
        skill,
        technique,
        phase,
        hypothesis_id,
        vuln_class,
        cand_source,
    ) = _validate_record_ptt_inputs(a, doc, pending)

    reservation, digest, early_response = _prepare_record_ptt_delivery(
        eng_dir, task, skill, phase, vuln_class, cand_source
    )
    if early_response is not None:
        return early_response

    with state.workflow_lock(eng_dir):
        doc = ptt.parse_ptt(_eng_path(eng_dir) / "state" / "ptt.md")
        pending = state.get_pending_sync(eng_dir)
        _validate_record_ptt_inputs(a, doc, pending)
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
            title=a.get("title"),
            raw_phase=a.get("phase"),
        )


def _handle_review_batch_skill_reservation(
    engagement: Path, pending: dict, a: dict, skill: str
) -> tuple[dict, str | None]:
    """Handle an optional explicit review-skill reservation.

    Returns (updated_a, early_response_json_or_None).
    """
    tasks = ptt.parse_ptt(engagement / "state" / "ptt.md")
    task_id = str(a.get("id") or "").strip()
    task = next((item for item in tasks if item.id == task_id), None)
    if task is None:
        raise ValueError(f"batch task {task_id!r} is missing from the PTT")
    hypothesis_id = str(a.get("hypothesis_id") or "").strip()
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
        adapter_cls = _get_skill_view_adapter()
        viewed = adapter_cls().view(skill, task_id=task_id)
        completed = complete_delivery(engagement, reservation, viewed)
        spec = skill_spec(skill)
        return a, _json(
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
        return a, _json("skill_preparing", transition_applied=False, released=False)
    updated_a = {**a, "note": _with_skill_token(str(a.get("note") or ""), skill, digest)}
    return updated_a, None


def _execute_batch_review(engagement: Path, pending: dict, a: dict, skill: str) -> str:
    """Validate and execute the core batch review transition."""
    context = _validate_review_batch(a, pending)
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
    supplied_evidence = [str(item) for item in (a.get("evidence_paths") or [])]
    evidence_paths = sorted(set(supplied_evidence) | set(batch_evidence))
    semantic = state.record_semantic_review(
        engagement,
        task_id=context["task_id"],
        hypothesis_id=str(a.get("hypothesis_id") or ""),
        skill=skill or "review",
        technique=str(a.get("technique") or "batch-review"),
        outcome=str(a.get("outcome") or "progress"),
        evidence_paths=evidence_paths,
        next_action=str(a.get("next_action") or "review evidence"),
        next_technique=str(a.get("next_technique") or ""),
        research_attempted=bool(a.get("research_attempted")),
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


@_serialise_errors
def handle_review_batch(a, **kwargs):
    """Review one completed batch, optionally record a finding, and release its lock."""
    eng_dir = str(a.get("eng_dir") or "").strip()
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
            skill = str(a.get("skill") or "").strip()
            binding_skill = str(binding.get("skill") or "")
            if skill and skill not in (binding_skill, "fp-check"):
                raise ValueError(
                    f"review skill {skill!r} does not match the expected binding skill {binding_skill!r}"
                )
            review_skill = skill or binding_skill
            a = {
                **a,
                "skill": review_skill,
                "hypothesis_id": str(a.get("hypothesis_id") or binding.get("hypothesis_id") or ""),
                "technique": str(a.get("technique") or binding.get("technique") or "batch-review"),
            }
            # A normal review certifies the active execution skill binding.
            # An fp-check or explicit review receipt is prepared separately if a skill is explicitly requested.
            if skill:
                a, early_response = _handle_review_batch_skill_reservation(
                    engagement, pending, a, review_skill
                )
                if early_response is not None:
                    return early_response
            return _execute_batch_review(engagement, pending, a, review_skill)
    except (OSError, ValueError) as exc:
        return _json(
            "blocked",
            released=False,
            error=str(exc),
            next_action="Resolve the reported batch, PTT, history, or finding issue and retry violin_review_batch",
        )


def _rebind_fields(a) -> tuple[str, str, str, str, str]:
    if a.get("confirm") is not True:
        raise ValueError("explicit confirm=true is required to rebind a pending batch")
    values = tuple(
        str(a.get(key) or "").strip()
        for key in ("eng_dir", "batch_id", "current_task_id", "replacement_task_id", "note")
    )
    if not all(values):
        raise ValueError(
            "eng_dir, batch_id, current_task_id, replacement_task_id, and note are required"
        )
    return values


def _validate_pending_identity(pending: dict, batch_id: str, current_task_id: str) -> None:
    actual_batch_id = str(pending.get("batch_id") or "")
    if actual_batch_id != batch_id:
        raise ValueError(
            f"stale batch id {batch_id!r}; current pending batch is {actual_batch_id!r}"
        )
    captured_task_id = str(pending.get("ptt_task_id") or "")
    if captured_task_id != current_task_id:
        raise ValueError(
            f"current task {current_task_id!r} does not match batch task {captured_task_id!r}"
        )


def _validate_pending_history(eng_dir: str, pending: dict) -> None:
    missing = next(
        (
            str(item.get("command") or "")
            for item in pending.get("commands") or []
            if item.get("command") and not history_contains(eng_dir, str(item.get("command")))
        ),
        "",
    )
    if missing:
        raise ValueError(
            f"pending command not yet in exact history: {missing!r}; "
            "wait for the batch to finish before rebinding"
        )


def _validated_replacement_task(
    eng_dir: str, pending: dict, current_task_id: str, replacement_task_id: str
):
    tasks = ptt.parse_ptt(_eng_path(eng_dir) / "state" / "ptt.md")
    if ptt.validate_ptt(tasks).errors:
        raise ValueError("PTT must have exactly one valid active task before rebinding")
    by_id = {task.id: task for task in tasks}
    if current_task_id not in by_id:
        raise ValueError(f"current batch task {current_task_id!r} is missing from the PTT")
    replacement = by_id.get(replacement_task_id)
    if replacement is None:
        raise ValueError(f"replacement task {replacement_task_id!r} is missing from the PTT")
    active = ptt.find_active_task(tasks)
    if active is None or active.id != replacement_task_id:
        raise ValueError(
            f"replacement task {replacement_task_id!r} must be the sole active [~] task"
        )
    phases = {
        str(item.get("phase") or pending.get("phase") or "")
        for item in pending.get("commands") or []
    } - {""}
    incompatible = sorted(
        phase for phase in phases if not ptt.task_matches_phase(replacement, phase)
    )
    if incompatible:
        raise ValueError(
            f"replacement task {replacement_task_id!r} is not phase-compatible with "
            + ", ".join(incompatible)
        )
    return replacement


@_serialise_errors
def handle_rebind_pending_batch(a, **kwargs):
    """Explicitly move a completed pending batch to another active PTT task."""

    try:
        eng_dir, batch_id, current_task_id, replacement_task_id, note = _rebind_fields(a)
        pending = state.get_pending_sync(eng_dir)
        if not pending:
            raise ValueError("no pending execution batch")
        _validate_pending_identity(pending, batch_id, current_task_id)
        _validate_pending_history(eng_dir, pending)
        _validated_replacement_task(eng_dir, pending, current_task_id, replacement_task_id)
        audit = state.rebind_pending_sync(
            eng_dir,
            expected_batch_id=batch_id,
            current_task_id=current_task_id,
            replacement_task_id=replacement_task_id,
            note=note,
        )
        return _json(
            "ok",
            batch_id=batch_id,
            ptt_task_id=replacement_task_id,
            ptt_reviewed=False,
            audit=audit,
        )
    except Exception as e:
        return _json("error", error=str(e))
