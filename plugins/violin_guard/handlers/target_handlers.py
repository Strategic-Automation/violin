"""Target resolution and status reporting handlers."""

from __future__ import annotations

import contextlib
from pathlib import Path

import yaml

from .. import bootstrap, command, ptt, runtime_backend, state
from ..phases import Phase, requires_hypothesis, suppresses_heartbeat
from ..skill_policy import resolve_skill_route
from ..skill_receipts import binding_readiness
from ..targets import resolve_target
from .base import _eng_path, _json, _serialise_errors


@_serialise_errors
def handle_target(a, **kwargs):
    """Resolve a target value from scope.yaml."""
    canonical = (_eng_path(a["eng_dir"]) / "scope" / "scope.yaml").resolve()
    scope_path_arg = str(a.get("scope") or "").strip()
    if scope_path_arg and Path(scope_path_arg).expanduser().resolve() != canonical:
        return _json(
            "blocked",
            error="runtime target resolution must use the engagement's canonical scope.yaml",
        )
    p = canonical

    if not p.exists():
        return _json("error", error=f"scope file not found: {p}")

    try:
        scope_data = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
    except Exception as exc:
        return _json("error", error=f"failed to parse scope: {exc}")

    value = resolve_target(
        scope_data,
        role=a.get("role"),
        host_query=a.get("host"),
        field=a.get("field") or "ip",
    )
    if value is None:
        return _json("error", error="no targets in scope")
    return _json("ok", value=value)


def _evaluate_status_blockers(
    eng_dir: Path,
    bootstrap_result,
    ptt_result,
    active,
    session_id: str | None,
    binding_reason: str | None,
    pending: dict | None,
    credit: int,
    current_phase: str | None,
) -> list[dict]:
    """Evaluate and collect all current engagement workflow blockers."""
    blockers = [
        {
            "code": "bootstrap",
            "reason": error,
            "next_action": "Run check-bootstrap and repair the named engagement artifact",
        }
        for error in bootstrap_result.errors
    ]
    if not session_id:
        blockers.append(
            {
                "code": "skill_session_unknown",
                "reason": "No session id is recorded for receipt-backed skill delivery",
                "next_action": "Use violin_record_ptt to select and prepare a routed skill",
            }
        )
    elif active and binding_reason:
        blockers.append(
            {
                "code": "skill_binding_required",
                "reason": binding_reason,
                "next_action": (
                    "Prepare the routed skill, then repeat the PTT update after its tool result "
                    "returns to the model"
                ),
            }
        )
    blockers.extend(
        {
            "code": "ptt",
            "reason": error,
            "next_action": "Use violin_record_ptt to leave exactly one phase-compatible [~] task",
        }
        for error in ptt_result.errors
    )
    if pending and credit == 0:
        blockers.append(
            {
                "code": "sync_required",
                "reason": "The bounded command batch is complete and still locked",
                "next_action": (
                    "Review its evidence, then call violin_review_batch with the active task"
                ),
            }
        )
    heartbeat_pending = state.has_heartbeat_pending(eng_dir)
    if heartbeat_pending:
        suppressed = False
        if current_phase:
            with contextlib.suppress(ValueError):
                suppressed = suppresses_heartbeat(ptt.normalize_phase(current_phase))
        if not suppressed:
            blockers.append(
                {
                    "code": "heartbeat_required",
                    "reason": state.get_heartbeat_reason(eng_dir) or "Periodic review is pending",
                    "next_action": "Review engagement state, then call violin_heartbeat_done",
                }
            )
    return blockers


def _build_phase_requirements() -> dict:
    """Build requirement mapping for all phases."""
    return {
        phase.value: {
            "ptt_phase": "EXPLOITATION" if phase is Phase.POST_EXPLOITATION else phase.value,
            "hypothesis_required": requires_hypothesis(phase),
            "sync_window": state.sync_credit_limit(phase.value),
            "accepted_scope_actions": command.accepted_action_aliases(phase),
            "heartbeat_enabled": not suppresses_heartbeat(phase),
        }
        for phase in Phase
    }


def _build_status_skill_summary(
    session_id: str | None,
    binding,
    binding_reason: str | None,
    route,
    legacy_marker: str | None,
) -> dict:
    """Format skill binding and route summary dictionary."""
    return {
        "session_id": session_id or None,
        "binding": binding,
        "binding_ready": binding_reason is None,
        "binding_reason": binding_reason,
        "route_candidates": list(route.allowed),
        "legacy_marker": legacy_marker,
        "legacy_marker_status": "obsolete" if legacy_marker else "absent",
        "recovery": (
            "Select a route candidate with violin_record_ptt; repeat after the preparation "
            "result returns to the model"
        ),
    }


@_serialise_errors
def handle_status(a, **kwargs):
    if not str(a.get("eng_dir") or "").strip():
        raise ValueError("eng_dir is required")
    eng_dir = state.resolve_eng_dir(a.get("eng_dir", ""))
    bootstrap_result = bootstrap.check_bootstrap(eng_dir, auto_repair=False)
    tasks = ptt.parse_ptt(eng_dir / "state" / "ptt.md")
    ptt_result = ptt.validate_ptt(tasks)
    active = ptt.find_active_task(tasks) if not ptt_result.errors else None
    current_phase = active.phase if active else None
    pending = state.get_pending_sync(eng_dir)
    credit_limit = int(
        (pending or {}).get("credit_limit") or state.sync_credit_limit(current_phase)
    )
    credit = state.sync_credit_remaining(eng_dir, current_phase)
    counts = state.read_counts(eng_dir)
    session_id = state.resolve_session_id(eng_dir)
    marker = eng_dir / "state" / f".skill-loaded-{session_id}" if session_id else None
    legacy_marker = str(marker) if marker and marker.is_file() else None
    binding, binding_reason = (
        binding_readiness(eng_dir, task_id=active.id, session_id=session_id)
        if active and session_id
        else (None, "no active task or session")
    )
    route = resolve_skill_route(current_phase or "RECON")

    blockers = _evaluate_status_blockers(
        eng_dir,
        bootstrap_result,
        ptt_result,
        active,
        session_id,
        binding_reason,
        pending,
        credit,
        current_phase,
    )
    phase_requirements = _build_phase_requirements()
    pending_commands = [
        {"command": item.get("command", ""), "required_phase": item.get("phase", "")}
        for item in (pending or {}).get("commands") or []
    ]
    heartbeat_pending = state.has_heartbeat_pending(eng_dir)

    return _json(
        "blocked" if blockers else "ok",
        engagement=str(eng_dir),
        current_task=active.id if active else None,
        current_task_title=active.title if active else None,
        current_phase=current_phase,
        command_phase_rule=(
            "Every target command must declare the active task phase; POST_EXPLOITATION uses an "
            "EXPLOITATION PTT task"
        ),
        phase_requirements=phase_requirements,
        blockers=blockers,
        pending_batch={
            "batch_id": (pending or {}).get("batch_id"),
            "task_id": (pending or {}).get("ptt_task_id"),
            "ptt_reviewed": bool((pending or {}).get("ptt_reviewed")),
            "commands": pending_commands,
        }
        if pending
        else None,
        sync_credit_remaining=credit,
        sync_credit_limit=credit_limit,
        heartbeat_pending=heartbeat_pending,
        heartbeat_reason=state.get_heartbeat_reason(eng_dir),
        command_count=counts["commands"],
        message_count=counts["messages"],
        skill=_build_status_skill_summary(
            session_id, binding, binding_reason, route, legacy_marker
        ),
        runtime=runtime_backend.runtime_readiness(eng_dir),
    )
