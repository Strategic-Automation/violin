"""Execution, check-command, and cancellation handlers."""

from __future__ import annotations

import os
from pathlib import Path

from .. import execution, ptt, state
from .base import (
    _check_command_internal,
    _eng_path,
    _json,
    _result,
    _serialise_errors,
)


@_serialise_errors
def handle_check_command(a, **kwargs):
    r = _check_command_internal(a)
    status_name = "ok" if r.exit_code() == 0 else "review" if r.exit_code() == 2 else "block"
    return _json(status_name, **_result(r))


@_serialise_errors
def handle_heartbeat_done(a, **kwargs):
    state.clear_heartbeat_pending(a["eng_dir"])
    return _json("ok")


@_serialise_errors
def handle_exec(a, **kwargs):
    r = _check_command_internal(a)
    exit_code = r.exit_code()
    status_name = "ok" if exit_code == 0 else "review" if exit_code == 2 else "block"
    if status_name not in ("ok",) and not (
        status_name == "review" and os.environ.get("HERMES_YOLO_MODE") == "1"
    ):
        sync_status = (
            "sync_required"
            if any("sync-credit" in str(x) or "not synced" in str(x) for x in r.errors)
            else "denied"
        )
        return _json(sync_status, executed=False, **_result(r))
    try:
        active_task = ptt.find_active_task(
            ptt.parse_ptt(_eng_path(a["eng_dir"]) / "state" / "ptt.md")
        )
        res = execution.execute(
            command=a["command"],
            eng_dir=a["eng_dir"],
            phase=a["phase"],
            backend=a.get("backend", "auto"),
            timeout_seconds=a.get("timeout_seconds", 180),
            cwd=a.get("cwd", ""),
            label=a.get("label", ""),
            ptt_task_id=active_task.id if active_task else "",
            argv=a.get("_argv"),
            background=bool(a.get("background", False)),
        )
        res.pop("status", None)
        return _json("ok", **res)
    except Exception as e:
        return _json("execution_failed", error=str(e), executed=False)


@_serialise_errors
def handle_exec_status(a, **kwargs):
    return _json("ok", **execution.status(a.get("eng_dir"), a.get("execution_id")))


@_serialise_errors
def handle_exec_cancel(a, **kwargs):
    return _json("ok", **execution.cancel(a.get("eng_dir"), a.get("execution_id")))


@_serialise_errors
def handle_exec_burst(a, **kwargs):
    """Single-approval bounded command batch with real burst semantics."""
    eng_dir = a.get("eng_dir", "")
    phase = a.get("phase", "")
    scope = a.get("scope", "")
    session_id = a.get("session_id", "")
    label = a.get("label", "")
    backend = a.get("backend", "auto")
    timeout_seconds = a.get("timeout_seconds", 180)
    cwd = a.get("cwd", "")
    continue_on_error = bool(a.get("continue_on_error", False))

    cmds = list(a.get("commands") or [])
    commands_file = a.get("commands_file")
    if commands_file:
        p = Path(commands_file)
        if not p.exists():
            return _json("error", error=f"commands file not found: {commands_file}")
        cmds.extend(
            line.strip() for line in p.read_text(encoding="utf-8").splitlines() if line.strip()
        )
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
            "target": a.get("target"),
        }
        r = _check_command_internal(cmd_args)
        exit_code = r.exit_code()
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
                        "errors": r.errors,
                    }
                ],
                reason=f"command [{idx + 1}] blocked: {r.errors[0] if r.errors else 'blocked'}",
            )
        review_warnings = r.warnings if status_name == "review" else []
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
            res.pop("status", None)
            entry = {"index": idx + 1, "command": cmd, **res}
            if review_warnings:
                entry["review_required"] = True
                entry["warnings"] = review_warnings
            results.append(entry)
            if res.get("executed"):
                executed += 1
            if (
                reservation_id
                and not item["local"]
                and not res.get("sync_reservation_consumed")
                and not res.get("sync_reservation_released")
            ):
                if res.get("executed"):
                    state.consume_reserved_sync_credit(eng_dir, reservation_id)
                else:
                    state.release_reserved_sync_credit(eng_dir, reservation_id)
            if res.get("exit_code", 0) != 0 and not continue_on_error:
                break
        except Exception as e:  # noqa: BLE001
            if reservation_id:
                state.release_reserved_sync_credit(eng_dir, reservation_id)
            if not continue_on_error:
                return _json(
                    "execution_failed",
                    executed=executed,
                    results=results + [{"index": idx + 1, "command": cmd, "error": str(e)}],
                    error=str(e),
                )
            results.append({"index": idx + 1, "command": cmd, "error": str(e)})

    if reservation_id:
        state.release_reserved_sync_credit(eng_dir, reservation_id)

    return _json(
        "batch_complete",
        executed=executed,
        results=results,
        review_required=any(item.get("review_required") for item in results),
    )
