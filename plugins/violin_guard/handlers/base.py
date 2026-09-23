"""Shared base utilities and error serialization wrappers for tool handlers."""

from __future__ import annotations

import hashlib
import json
import logging
from datetime import UTC, datetime
from functools import wraps
from pathlib import Path
from typing import Any

from ..core import hypotheses, state
from ..core.skill_policy import routable_context, skill_spec
from ..core.skill_receipts import (
    HermesSkillViewAdapter,
    complete_delivery,
    get_binding,
    prepare_delivery,
)
from ..gates import command as cmd_module
from ..gates.command import CheckCommandArgs

logger = logging.getLogger(__name__)


def _running_background_command(eng_dir: str, command: str) -> bool:
    """Return True if command is currently running as an acknowledged background process."""
    exec_dir = _eng_path(eng_dir) / "evidence" / "executions"
    if not exec_dir.exists():
        return False
    for path in exec_dir.glob("*.json"):
        if path.name.endswith(".lock") or path.name.endswith(".tmp"):
            continue
        record = state.read_json(path)
        if (
            isinstance(record, dict)
            and record.get("background")
            and record.get("command") == command
            and record.get("status") in {"running", "starting"}
        ):
            return True
    return False


def _eng_path(eng_dir: str) -> Path:
    return state.resolve_eng_dir(eng_dir)


def _json(status_name: str, **payload) -> str:
    payload.pop("status", None)
    return json.dumps({"schema_version": 2, "status": status_name, **payload})


def _hypothesis_route_context(eng_dir: str | Path, hypothesis_id: str) -> tuple[str, str]:
    """Return the routable (vuln_class, candidate_source) a hypothesis records."""

    record = hypotheses.find_by_id(_eng_path(str(eng_dir)) / "hypotheses.md", hypothesis_id)
    if record is None:
        return "", ""
    return routable_context(record.vuln_class, record.candidate_source)


def _bound_route_context(eng_dir: str | Path, task_id: str) -> tuple[str, str]:
    """Resolve a task's routing context from the hypothesis its binding records.

    ``violin_record_ptt`` routes from the hypothesis ``vuln_class``, but a caller
    that passes no context resolves from the phase default instead, so the same
    task demanded two different skills depending on which tool asked. Reading the
    bound hypothesis here gives every caller one answer; the phase default stays
    as the fallback for a task with no binding.
    """

    hypothesis_id = str((get_binding(eng_dir, task_id) or {}).get("hypothesis_id") or "").strip()
    if not hypothesis_id:
        return "", ""
    return _hypothesis_route_context(eng_dir, hypothesis_id)


def _prepare_skill_reservation_payload(
    eng_dir: str | Path,
    *,
    skill: str,
    phase: str,
    task_id: str,
    session_fallback: str = "ptt",
    vulnerability_class: str | None = None,
    candidate_source: str | None = None,
    extra_fields: dict[str, Any] | None = None,
    adapter_cls: Any = HermesSkillViewAdapter,
) -> tuple[Any, str, str | None]:
    if not vulnerability_class and not candidate_source:
        vulnerability_class, candidate_source = _bound_route_context(eng_dir, task_id)
    digest = "sha256:" + hashlib.sha256(f"policy:{skill}".encode()).hexdigest()
    reservation = prepare_delivery(
        eng_dir,
        session_id=state.resolve_session_id(eng_dir) or session_fallback,
        skill=skill,
        bundle_digest=digest,
        phase=phase,
        vulnerability_class=vulnerability_class or None,
        candidate_source=candidate_source or None,
    )
    if reservation.owner:
        viewed = adapter_cls().view(skill, task_id=task_id)
        completed = complete_delivery(eng_dir, reservation, viewed)
        spec = skill_spec(skill)
        early_resp = _json(
            "skill_prepared" if completed.status == "delivered" else "skill_unavailable",
            transition_applied=False,
            **(extra_fields or {}),
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
            "skill_preparing",
            transition_applied=False,
            **(extra_fields or {}),
            skill={"name": skill, "digest": digest},
        )
        return reservation, digest, early_resp
    return reservation, digest, None


def _result(result) -> dict[str, list[str]]:
    hints = getattr(result, "hints", [])
    return {
        "errors": result.errors,
        "warnings": result.warnings,
        "infos": result.infos,
        "hints": hints,
    }


def _log_guard_friction(eng_dir: Path, result, command: str) -> None:
    """Append a guard-authored friction row to state/guard_feedback.md when the
    guard blocks or reviews.

    Guard rows live in their own file under their own heading — a distinct
    column schema from the agent-maintained framework_feedback.md table — so a
    guard-side write can never invalidate an agent edit queued against
    framework_feedback.md. Only writes for feedback-enabled engagements:
    engagement initialization creates state/framework_feedback.md, which marks
    the engagement as opted in. Recording here means friction is captured at
    the moment it happens, with zero agent bookkeeping, so the agent never has
    to reconstruct what was blocked from memory at the end of the run.
    """
    feedback_marker = eng_dir / "state" / "framework_feedback.md"
    if not feedback_marker.exists() or result.exit_code() == 0:
        return
    rows = [("Guard Block", err) for err in result.errors]
    if result.exit_code() == 2:
        rows.extend([("Guard Review", warn) for warn in result.warnings])
    if not rows:
        return
    guard_file = eng_dir / "state" / "guard_feedback.md"
    existing = (
        guard_file.read_text(encoding="utf-8", errors="replace") if guard_file.exists() else ""
    )
    now = datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S UTC")
    lines = []
    for category, issue in rows:
        safe = str(issue).replace("|", "\\|").replace("\n", " ").strip()
        if safe in existing:  # avoid spam from repeated identical failures
            continue
        lines.append(
            f"| {now} | {category} | {safe} | "
            f"command blocked: {command[:100]} | "
            f"use violin_record_hypothesis / violin_record_ptt / violin_exec with valid inputs |"
        )
    if not lines:
        return
    with state.lock_file(guard_file), guard_file.open("a", encoding="utf-8") as fh:
        if not existing:
            fh.write(
                "# Violin Guard Friction Log\n"
                "\n"
                "Automated guard block/review records. This file is distinct from the "
                "agent-maintained state/framework_feedback.md table by design: the guard "
                "never writes into the file the agent patches.\n"
                "\n"
                "| Timestamp | Category | Issue | Impact | Prevention |\n"
                "|---|---|---|---|---|\n"
            )
        fh.write("\n".join(lines) + "\n")


def _check_command_internal(args: dict[str, Any]) -> cmd_module.CheckResult:
    result = cmd_module.check_command(
        CheckCommandArgs(
            command=args.get("command", ""),
            phase=args.get("phase", ""),
            eng_dir=args.get("eng_dir", ""),
            scope=args.get("scope", ""),
            target=args.get("target"),
            session_id=args.get("session_id"),
            hypothesis_id=args.get("hypothesis_id"),
            is_burst=bool(args.get("is_burst", False)),
        )
    )
    try:
        eng_path = state.resolve_eng_dir(args.get("eng_dir", ""))
    except Exception:  # noqa: BLE001 — logging must never break the gate
        eng_path = None
    if eng_path is not None and result.exit_code() != 0:
        _log_guard_friction(eng_path, result, args.get("command", ""))
    return result


def _serialize_errors(fn):
    """Keep every model-visible handler on the stable JSON response contract."""

    @wraps(fn)
    def wrapped(args=None, **kwargs):
        try:
            return fn(args or {}, **kwargs)
        except (ValueError, TypeError, OSError, KeyError) as exc:
            return _json("error", error=str(exc))
        except Exception as exc:
            logger.exception("Unexpected handler error during execution: %s", exc)
            return _json("error", error=str(exc))

    return wrapped
