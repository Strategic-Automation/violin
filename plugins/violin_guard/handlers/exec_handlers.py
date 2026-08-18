"""Execution, check-command, and cancellation handlers."""

from __future__ import annotations

import os
from pathlib import Path

from ..core import ptt, state
from ..engine import execution
from .base import (
    _check_command_internal,
    _eng_path,
    _json,
    _result,
    _serialize_errors,
)

_MAX_COMMAND_FILE_BYTES = 64 * 1024


def _commands_from_file(eng_dir: str, value: str) -> list[str]:
    """Load a bounded engagement-local command file without following symlinks."""
    relative = Path(value)
    if relative.is_absolute():
        raise ValueError("commands_file must be engagement-relative")
    engagement = _eng_path(eng_dir).resolve()
    candidate = engagement / relative
    if candidate.is_symlink():
        raise ValueError("commands_file must not be a symlink")
    resolved = candidate.resolve()
    if not resolved.is_relative_to(engagement):
        raise ValueError("commands_file escapes the engagement directory")
    current = candidate
    while current != engagement:
        if current.is_symlink():
            raise ValueError("commands_file must not traverse symlinked directories")
        current = current.parent
    if not resolved.exists():
        raise ValueError(f"commands file not found: {value}")
    if not resolved.is_file():
        raise ValueError("commands_file must be a regular file")
    if resolved.stat().st_size > _MAX_COMMAND_FILE_BYTES:
        raise ValueError(f"commands_file exceeds {_MAX_COMMAND_FILE_BYTES} bytes")
    return [
        line.strip() for line in resolved.read_text(encoding="utf-8").splitlines() if line.strip()
    ]


@_serialize_errors
@_serialize_errors
def handle_heartbeat_done(args: dict, **kwargs):
    state.clear_heartbeat_pending(args["eng_dir"])
    return _json("ok")


@_serialize_errors
def handle_exec(args: dict, *, _internal_argv=None, _internal_background=None, **kwargs):
    result = _check_command_internal(args)
    exit_code = result.exit_code()
    status_name = "ok" if exit_code == 0 else "review" if exit_code == 2 else "block"
    if status_name not in ("ok",) and not (
        status_name == "review" and os.environ.get("HERMES_YOLO_MODE") == "1"
    ):
        sync_status = (
            "sync_required"
            if any(
                "sync-credit" in str(error_item) or "not synced" in str(error_item)
                for error_item in result.errors
            )
            else "denied"
        )
        return _json(sync_status, executed=False, **_result(result))
    try:
        active_task = ptt.find_active_task(
            ptt.parse_ptt(_eng_path(args["eng_dir"]) / "state" / "ptt.md")
        )
        res = execution.execute(
            command=args["command"],
            eng_dir=args["eng_dir"],
            phase=args["phase"],
            backend=args.get("backend", "auto"),
            timeout_seconds=args.get("timeout_seconds", 180),
            cwd=args.get("cwd", ""),
            label=args.get("label", ""),
            ptt_task_id=active_task.id if active_task else "",
            argv=_internal_argv,
            background=(
                bool(args.get("background", False))
                if _internal_background is None
                else bool(_internal_background)
            ),
        )
        execution_status = res.pop("status", None)
        if not res.get("executed"):
            return _json(
                "execution_failed",
                execution_status=execution_status,
                error=res.get("stderr_preview") or "process failed to start",
                **res,
            )
        hint = (
            "record this result on the hypothesis board now (violin_record_hypothesis: "
            "status, Test Response, Runtime Evidence path) and link a canonical "
            "FIND-NNN.md before the next command"
            if active_task
            else ""
        )
        return _json("ok", execution_status=execution_status, next_action=hint, **res)
    except Exception as exc:
        return _json("execution_failed", error=str(exc), executed=False)


@_serialize_errors
def handle_exec_status(args: dict, **kwargs):
    return _json("ok", **execution.status(args.get("eng_dir"), args.get("execution_id")))


@_serialize_errors
def handle_exec_cancel(args: dict, **kwargs):
    return _json("ok", **execution.cancel(args.get("eng_dir"), args.get("execution_id")))


@_serialize_errors
def handle_exec_burst(args: dict, **kwargs):
    """Single-approval bounded command batch with real burst semantics."""
    eng_dir = args.get("eng_dir", "")
    phase = args.get("phase", "")
    scope = args.get("scope", "")
    session_id = args.get("session_id", "")
    label = args.get("label", "")
    backend = args.get("backend", "auto")
    timeout_seconds = args.get("timeout_seconds", 180)
    cwd = args.get("cwd", "")
    continue_on_error = bool(args.get("continue_on_error", False))

    cmds = list(args.get("commands") or [])
    commands_file = args.get("commands_file")
    if commands_file:
        try:
            cmds.extend(_commands_from_file(eng_dir, str(commands_file)))
        except ValueError as exc:
            return _json("error", error=str(exc))
    if not cmds:
        return _json("error", error="no commands provided (inline or commands_file)")
    if len(cmds) > state.MAX_BURST_COMMANDS:
        return _json("error", error=f"burst limit is {state.MAX_BURST_COMMANDS}")
    active_task = ptt.find_active_task(ptt.parse_ptt(_eng_path(eng_dir) / "state" / "ptt.md"))
    active_task_id = active_task.id if active_task else ""

    preflight = []
    required_slots = 0
    for idx, cmd in enumerate(cmds):
        cmd_args = {
            "command": cmd,
            "phase": phase,
            "eng_dir": eng_dir,
            "scope": scope,
            "session_id": session_id,
            "target": args.get("target"),
        }
        cmd_result = _check_command_internal(cmd_args)
        exit_code = cmd_result.exit_code()
        status_name = "ok" if exit_code == 0 else "review" if exit_code == 2 else "block"
        if status_name == "block":
            return _json(
                "denied",
                executed=0,
                results=[
                    {
                        "index": idx + 1,
                        "command": cmd,
                        "status": "blocked",
                        "errors": cmd_result.errors,
                    }
                ],
                reason=f"command [{idx + 1}] blocked: {cmd_result.errors[0] if cmd_result.errors else 'blocked'}",
            )
        review_warnings = cmd_result.warnings if status_name == "review" else []
        local = state.is_local_bookkeeping_command(cmd)
        if not local:
            required_slots += 1
        preflight.append(
            {
                "index": idx + 1,
                "command": cmd,
                "review_warnings": review_warnings,
                "local": local,
            }
        )

    reservation_id = None
    if required_slots:
        try:
            reservation_id = state.reserve_sync_credit(eng_dir, phase, required_slots)
        except ValueError as exc:
            return _json("denied", executed=0, results=[], reason=str(exc))

    results = []
    executed = 0
    try:
        for item in preflight:
            idx = item["index"]
            cmd = item["command"]
            review_warnings = item["review_warnings"]
            try:
                res = execution.execute(
                    command=cmd,
                    eng_dir=eng_dir,
                    phase=phase,
                    backend=backend,
                    timeout_seconds=timeout_seconds,
                    cwd=cwd,
                    label=label,
                    ptt_task_id=active_task_id,
                    sync_reservation=None if item["local"] else reservation_id,
                )
                execution_status = res.pop("status", None)
                entry = {
                    "index": idx,
                    "command": cmd,
                    "execution_status": execution_status,
                    **res,
                }
                if review_warnings:
                    entry["review_required"] = True
                    entry["warnings"] = review_warnings
                results.append(entry)
                if res.get("executed"):
                    executed += 1
                if res.get("exit_code", 0) != 0 and not continue_on_error:
                    break
            except Exception as exc:  # noqa: BLE001
                if not continue_on_error:
                    return _json(
                        "execution_failed",
                        executed=executed,
                        results=results + [{"index": idx, "command": cmd, "error": str(exc)}],
                        error=str(exc),
                    )
                results.append({"index": idx, "command": cmd, "error": str(exc)})
    finally:
        if reservation_id:
            state.release_reserved_sync_credit(eng_dir, reservation_id)

    return _json(
        "batch_complete",
        executed=executed,
        results=results,
        review_required=any(item.get("review_required") for item in results),
    )
