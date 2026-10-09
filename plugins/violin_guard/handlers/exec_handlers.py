"""Execution, check-command, and cancellation handlers."""

from __future__ import annotations

import os
import time
from pathlib import Path

from ..core.engagement import ptt, state
from ..engine import execution
from .base import (
    _check_command_internal,
    _eng_path,
    _json,
    _result,
    _serialize_errors,
)

_MAX_COMMAND_FILE_BYTES = 64 * 1024


def _foreground_deadline() -> float | None:
    """Leave time for termination and receipts before Hermes abandons dispatch."""
    try:
        from agent.deadline import resolve_timeout
    except ImportError:
        deadlines = [420.0]  # Standalone administrative CLI has no Hermes runtime.
    else:
        concurrent = resolve_timeout(
            "tools.concurrent_batch", default=420.0, env_var="HERMES_CONCURRENT_TOOL_TIMEOUT_S"
        )
        deadlines = [
            concurrent,
            resolve_timeout("tools.sequential_call", default=concurrent),
        ]
    finite = [deadline for deadline in deadlines if deadline is not None]
    return time.monotonic() + min(finite) - 30 if finite else None


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
def handle_heartbeat_done(args: dict, **kwargs):
    state.clear_heartbeat_pending(args["eng_dir"])
    return _json("ok")


def _execution_allowed(exit_code: int) -> bool:
    """Use the same pre-execution authorization for single commands and batches."""
    return exit_code == 0 or (exit_code == 2 and os.environ.get("HERMES_YOLO_MODE") == "1")


@_serialize_errors
def handle_exec(args: dict, *, _internal_argv=None, _internal_background=None, **kwargs):
    background = (
        bool(args.get("background", False))
        if _internal_background is None
        else bool(_internal_background)
    )
    if not background:
        deadline = _foreground_deadline()
        if (
            deadline is not None
            and args.get("timeout_seconds", 180) + 10 >= deadline - time.monotonic()
        ):
            raise ValueError(
                "foreground timeout exceeds Hermes' tool deadline; use violin_exec with "
                "background=true and violin_exec_status/violin_exec_cancel for long commands"
            )
    result = _check_command_internal(args)
    exit_code = result.exit_code()
    if not _execution_allowed(exit_code):
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
            evidence_outputs=args.get("evidence_outputs", []),
            ptt_task_id=active_task.id if active_task else "",
            argv=_internal_argv,
            background=background,
        )
        execution_status = res.pop("status", None)
        if (
            not res.get("executed")
            or res.get("accounting_pending")
            or res.get("finalization_error")
        ):
            return _json(
                "execution_failed",
                execution_status=execution_status,
                error=res.get("accounting_error")
                or res.get("finalization_error")
                or res.get("stderr_preview")
                or "process failed to start",
                **res,
            )
        hint = (
            "record this result on the hypothesis board now (violin_record_hypothesis: "
            "status, Test Response, Runtime Evidence path) before the next command"
            if active_task
            else ""
        )
        return _json(
            "ok", execution_status=execution_status, next_action=hint, hints=result.hints, **res
        )
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
    """Authorize the complete bounded batch before executing any command."""
    deadline = _foreground_deadline()
    eng_dir = args.get("eng_dir", "")
    phase = args.get("phase", "")
    scope = args.get("scope", "")
    session_id = args.get("session_id", "")
    label = args.get("label", "")
    backend = args.get("backend", "auto")
    timeout_seconds = args.get("timeout_seconds", 180)
    cwd = args.get("cwd", "")
    continue_on_error = bool(args.get("continue_on_error", False))
    burst_evidence_outputs = list(args.get("evidence_outputs") or [])

    raw_commands = args.get("commands")
    if isinstance(raw_commands, str):
        # A doubled-encoded burst arrives as the JSON string of an array rather
        # than the array itself. Reject it naming the expected shape before any
        # command is admitted, so no receipt is ever written for the malformed
        # burst.
        return _json(
            "error",
            error=(
                "commands must be a list of strings; received a single "
                "(JSON-encoded) string — pass the decoded array, not its JSON text"
            ),
        )
    cmds = list(raw_commands or [])
    for command_index, cmd in enumerate(cmds):
        if not isinstance(cmd, str):
            return _json(
                "error",
                error=(
                    f"commands must be a list of strings; element "
                    f"{command_index + 1} is not a string"
                ),
            )
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
            "is_burst": True,
        }
        cmd_result = _check_command_internal(cmd_args)
        exit_code = cmd_result.exit_code()
        status_name = "ok" if exit_code == 0 else "review" if exit_code == 2 else "block"
        if not _execution_allowed(exit_code):
            denied_status = "blocked" if status_name == "block" else "review"
            reasons = cmd_result.errors or cmd_result.warnings
            return _json(
                "denied",
                executed=0,
                results=[
                    {
                        "index": idx + 1,
                        "command": cmd,
                        "status": denied_status,
                        **_result(cmd_result),
                    }
                ],
                reason=f"command [{idx + 1}] {denied_status}: {reasons[0] if reasons else denied_status}",
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
            return _json(
                "denied",
                executed=0,
                results=[],
                reason=(
                    f"{exc}. A burst costs one sync slot per target command: "
                    f"{required_slots} slot(s) for {len(preflight)} command(s) in phase "
                    f"{phase}. Split it into a smaller burst, or run violin_review_batch to "
                    "refresh the sync window."
                ),
            )

    results = []
    executed = 0
    stopped_after_index = None
    unstarted_count = required_slots
    try:
        for item in preflight:
            idx = item["index"]
            cmd = item["command"]
            review_warnings = item["review_warnings"]
            remaining = (
                timeout_seconds if deadline is None else int(deadline - time.monotonic()) - 10
            )
            if remaining <= 0:
                pending = state.get_pending_sync(eng_dir)
                return _json(
                    "batch_stopped",
                    executed=executed,
                    results=results,
                    review_required=bool(pending)
                    or any(item.get("review_required") for item in results),
                    pending_batch_id=(pending or {}).get("batch_id"),
                    stopped_after_index=idx - 1,
                    skipped=len(preflight) - len(results),
                    reason="Hermes foreground budget exhausted; use tracked background execution for long commands",
                )
            if not item["local"]:
                unstarted_count -= 1
            try:
                res = execution.execute(
                    command=cmd,
                    eng_dir=eng_dir,
                    phase=phase,
                    backend=backend,
                    timeout_seconds=min(timeout_seconds, remaining),
                    cwd=cwd,
                    label=label,
                    evidence_outputs=burst_evidence_outputs,
                    ptt_task_id=active_task_id,
                    sync_reservation=None if item["local"] else reservation_id,
                )
                if not item["local"] and not res.get("executed"):
                    unstarted_count += 1
                if res.get("accounting_pending") or res.get("finalization_error"):
                    res["review_required"] = True
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
                if (
                    res.get("accounting_pending")
                    or res.get("finalization_error")
                    or (res.get("exit_code", 0) != 0 and not continue_on_error)
                ):
                    stopped_after_index = idx
                    break
            except Exception as exc:  # noqa: BLE001
                if not continue_on_error or not item["local"]:
                    pending = state.get_pending_sync(eng_dir)
                    return _json(
                        "execution_failed",
                        executed=executed,
                        results=results + [{"index": idx, "command": cmd, "error": str(exc)}],
                        error=str(exc),
                        review_required=not item["local"]
                        or bool(pending)
                        or any(item.get("review_required") for item in results),
                        pending_batch_id=(pending or {}).get("batch_id"),
                        stopped_after_index=idx,
                        skipped=len(preflight) - idx,
                    )
                results.append({"index": idx, "command": cmd, "error": str(exc)})
    finally:
        if reservation_id:
            state.release_reserved_sync_credit(
                eng_dir, reservation_id, unstarted_count=unstarted_count
            )

    pending = state.get_pending_sync(eng_dir)
    return _json(
        "batch_stopped" if stopped_after_index is not None else "batch_complete",
        executed=executed,
        results=results,
        review_required=bool(pending) or any(item.get("review_required") for item in results),
        pending_batch_id=(pending or {}).get("batch_id"),
        **(
            {
                "stopped_after_index": stopped_after_index,
                "skipped": len(preflight) - len(results),
            }
            if stopped_after_index is not None
            else {}
        ),
    )
