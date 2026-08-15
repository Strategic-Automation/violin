"""Shared base utilities and error serialization wrappers for tool handlers."""

from __future__ import annotations

import json
import logging
from datetime import UTC, datetime
from functools import wraps
from pathlib import Path
from typing import Any

from .. import command as cmd_module
from .. import state
from ..command import CheckCommandArgs

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


def _result(r) -> dict[str, list[str]]:
    return {"errors": r.errors, "warnings": r.warnings, "infos": r.infos}


def _log_guard_friction(eng_dir: Path, result, command: str) -> None:
    """Append a framework_feedback.md row when the guard blocks or reviews.

    Only writes when state/framework_feedback.md already exists — engagement
    initialization creates it. Engagements without the file are untouched.
    Recording here means friction is captured at the moment it happens, with
    zero agent bookkeeping, so the agent never has to reconstruct what was
    blocked from memory at the end of the run.
    """
    feedback = eng_dir / "state" / "framework_feedback.md"
    if not feedback.exists():
        return
    rows = [("Guard Block", err) for err in result.errors] + [
        ("Guard Review", warn) for warn in result.warnings
    ]
    if not rows:
        return
    existing = feedback.read_text(encoding="utf-8", errors="replace")
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
    with feedback.open("a", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")


def _check_command_internal(a) -> cmd_module.CheckResult:
    result = cmd_module.check_command(
        CheckCommandArgs(
            command=a.get("command", ""),
            phase=a.get("phase", ""),
            eng_dir=a.get("eng_dir", ""),
            scope=a.get("scope", ""),
            target=a.get("target"),
            session_id=a.get("session_id"),
            hypothesis_id=a.get("hypothesis_id"),
        )
    )
    try:
        eng_path = state.resolve_eng_dir(a.get("eng_dir", ""))
    except Exception:  # noqa: BLE001 — logging must never break the gate
        eng_path = None
    if eng_path is not None and (result.errors or result.warnings):
        _log_guard_friction(eng_path, result, a.get("command", ""))
    return result


def _call(fn, args, **kwargs) -> Any:
    """Wrap a handler function with uniform error serialisation."""
    try:
        return fn(args or {}, **kwargs)
    except (ValueError, TypeError, OSError, KeyError) as exc:
        return _json("error", error=str(exc))
    except Exception as exc:
        logger.exception("Unexpected handler error during execution: %s", exc)
        return _json("error", error=str(exc))


def _serialise_errors(fn):
    """Keep every model-visible handler on the stable JSON response contract."""

    @wraps(fn)
    def wrapped(args=None, **kwargs):
        return _call(fn, args, **kwargs)

    return wrapped
