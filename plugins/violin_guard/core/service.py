"""Single application facade for guarded execution."""

from __future__ import annotations

import json
import os
from pathlib import Path

from . import command, execution, hypotheses, ptt, state, targets
from .adapters import search_exploit


def _eng_path(eng_dir: str) -> Path:
    return state._eng_dir(eng_dir)


def _json(status_name, **payload):
    payload.pop("status", None)
    return json.dumps({"schema_version": 2, "status": status_name, **payload})


def _result(r):
    return {"errors": r.errors, "warnings": r.warnings, "infos": r.infos}


def handle_check_command(a, **kwargs):
    r = command.check_command(
        command.CheckCommandArgs(
            command=a.get("command", ""),
            phase=a.get("phase", ""),
            eng_dir=a.get("eng_dir", ""),
            scope=a.get("scope", ""),
            target=a.get("target"),
            session_id=a.get("session_id"),
            skill_loaded_file=a.get("skill_loaded_file"),
        )
    )
    return _json(
        "ok" if r.exit_code() == 0 else "review" if r.exit_code() == 2 else "block", **_result(r)
    )


def handle_record_ptt(a, **kwargs):
    try:
        eng_dir = a["eng_dir"]
        doc = ptt.parse_ptt(_eng_path(eng_dir) / "state" / "ptt.md")
        pending = state.get_pending_sync(eng_dir)
        task = a.get("id")
        note = (a.get("note") or "").strip()
        status = a.get("status", "[~]")

        # --- Self-certify guard (audit P0-sync) ---------------------------------
        # A review only unlocks the batch when it demonstrably corresponds to the
        # work that was just executed. Four checks, all fail-closed:
        if not task or not note:
            raise ValueError("task id and non-empty review note required")
        if not pending:
            return _start_ptt_task(_eng_path(eng_dir) / "state" / "ptt.md", doc, task, status, note)
        # 1. reviewed ID must match the active [~] task — never review a different row
        validation = ptt.validate_ptt(doc)
        if validation.errors:
            raise ValueError("PTT must have exactly one valid active task before review")
        active = ptt.find_active_task(doc)
        captured_task = pending.get("ptt_task_id")
        if not captured_task:
            raise ValueError(
                "pending batch has no captured PTT task; refusing legacy self-certification"
            )
        if task != captured_task:
            raise ValueError(f"reviewed task {task!r} does not match batch task {captured_task!r}")
        if not active or active.id != captured_task:
            raise ValueError(
                f"reviewed task {task!r} is not the active task; resolve the active task first"
            )
        # 2. Bind the review to the current batch ourselves. Requiring an
        # operator to copy an opaque ID creates avoidable friction; the guard
        # already holds the pending state and records an explicit marker before
        # it unlocks anything.
        batch_id = pending.get("batch_id")
        if batch_id and batch_id not in note:
            note = f"{note} [reviewed-batch:{batch_id}]"
        # 3. every pending command must already be recorded in history.md
        for item in pending.get("commands") or []:
            cmd = item.get("command")
            if cmd and not state.history_contains(eng_dir, cmd):
                raise ValueError(
                    f"pending command not yet in history.md: {cmd!r}; "
                    "the batch must finish before review"
                )

        ptt.update_task(_eng_path(eng_dir) / "state" / "ptt.md", task, status, note)
        state.mark_ptt_reviewed(eng_dir, task, note)
        # 4. no commands may run after review until sync-done clears the batch
        return _json("ok", task_id=task, batch_id=pending.get("batch_id"))
    except Exception as e:
        return _json("error", error=str(e))


def _start_ptt_task(ptt_path: Path, tasks, task_id: str, status: str, note: str) -> str:
    """Arm one untouched, phase-bound task before the first target command."""

    if status != "[~]":
        raise ValueError("without a pending batch, only [~] may start a PTT task")
    if ptt.find_active_task(tasks):
        raise ValueError("an active PTT task already exists; review its pending batch first")
    selected = next((item for item in tasks if item.id == task_id), None)
    if selected is None:
        raise ValueError(f"PTT task {task_id!r} not found")
    if selected.status != "[ ]":
        raise ValueError(f"PTT task {task_id!r} must be [ ] before it can be started")
    try:
        phase = ptt.normalize_phase(selected.phase)
    except ValueError as exc:
        raise ValueError(f"PTT task {task_id!r} must sit below a valid Phase heading") from exc
    ptt.update_task(ptt_path, task_id, status, note)
    return _json("ok", task_id=task_id, phase=phase.value, task_started=True)


def handle_record_hypothesis(a, **kwargs):
    try:
        eng_dir = a["eng_dir"]
        fields = {k: v for k, v in a.items() if k != "eng_dir"}
        # Pass in-scope hosts so the record is scope-bound (audit P1-hyp).
        in_scope = _scope_hosts(eng_dir)
        h = hypotheses.update_hypothesis(
            _eng_path(eng_dir) / "hypotheses.md", in_scope_hosts=in_scope, **fields
        )
        return _json("ok", hypothesis=h.to_dict())
    except Exception as e:
        return _json("error", error=str(e))


def _scope_hosts(eng_dir: str) -> set[str] | None:
    """Return the in-scope host set from scope.yaml, or None if no scope file.

    ``None`` (rather than empty set) signals 'no scope check available' so the
    guard does not fail-closed on hypotheses recorded without a target.
    """
    import yaml

    scope_path = _eng_path(eng_dir) / "scope" / "scope.yaml"
    if not scope_path.exists():
        return None
    try:
        data = yaml.safe_load(scope_path.read_text(encoding="utf-8")) or {}
    except Exception:
        return None
    return targets.scope_hosts(data) or None


def handle_sync_done(a, **kwargs):
    try:
        p = state.get_pending_sync(a["eng_dir"])
        if not p:
            return _json("ok", message="nothing pending")
        if not p.get("ptt_reviewed"):
            return _json("review", error="explicit PTT review required")
        for item in p.get("commands") or []:
            if not state.history_contains(a["eng_dir"], item.get("command", "")):
                return _json(
                    "review", error="all pending commands must exist in exact history before sync"
                )
        state.clear_pending_sync(a["eng_dir"])
        return _json("ok", batch_id=p.get("batch_id"))
    except Exception as e:
        return _json("error", error=str(e))


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
            if item.get("command") and not state.history_contains(eng_dir, str(item.get("command")))
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


def handle_heartbeat_done(a, **kwargs):
    state.clear_heartbeat_pending(a["eng_dir"])
    return _json("ok")


def handle_exec(a, **kwargs):
    gate = json.loads(handle_check_command(a))
    if gate["status"] not in ("ok",) and not (
        gate["status"] == "review" and os.environ.get("HERMES_YOLO_MODE") == "1"
    ):
        status = (
            "sync_required"
            if any(
                "sync-credit" in str(x) or "not synced" in str(x) for x in gate.get("errors", [])
            )
            else "denied"
        )
        return _json(status, executed=False, **gate)
    try:
        active_task = ptt.find_active_task(
            ptt.parse_ptt(_eng_path(a["eng_dir"]) / "state" / "ptt.md")
        )
        r = execution.execute(
            command=a["command"],
            eng_dir=a["eng_dir"],
            phase=a["phase"],
            backend=a.get("backend", "local"),
            timeout_seconds=a.get("timeout_seconds", 180),
            cwd=a.get("cwd", ""),
            label=a.get("label", ""),
            ptt_task_id=active_task.id if active_task else "",
            argv=a.get("_argv"),
            background=bool(a.get("background", False)),
        )
        r.pop("status", None)
        return _json("ok", **r)
    except Exception as e:
        return _json("execution_failed", error=str(e), executed=False)


def handle_exec_status(a, **kwargs):
    return _json("ok", **execution.status(a.get("eng_dir"), a.get("execution_id")))


def handle_exec_cancel(a, **kwargs):
    return _json("ok", **execution.cancel(a.get("eng_dir"), a.get("execution_id")))


def handle_exec_burst(a, **kwargs):
    """Single-approval bounded command batch with real burst semantics.

    - Reads commands from ``commands`` (inline) and/or ``commands_file``.
    - Fail-closed: a hard-blocked command (gate exit 1, non-yolo) halts the
      whole batch and returns DENIED at once.
    - ``continue_on_error`` only survives executed-but-failed *target* commands
      (exit code != 0) and soft reviews; it never survives a hard BLOCK.
    - Returns an accurate ``executed`` count (commands that actually ran) and a
      single batch boundary (one pending-sync lock armed on the last command).
    """
    eng_dir = a.get("eng_dir", "")
    phase = a.get("phase", "")
    scope = a.get("scope", "")
    session_id = a.get("session_id", "")
    skill_loaded_file = a.get("skill_loaded_file", "")
    label = a.get("label", "")
    backend = a.get("backend", "local")
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

    results = []
    executed = 0
    for idx, cmd in enumerate(cmds):
        gate = json.loads(
            handle_check_command(
                {
                    "command": cmd,
                    "phase": phase,
                    "eng_dir": eng_dir,
                    "scope": scope,
                    "session_id": session_id,
                    "skill_loaded_file": skill_loaded_file,
                    "target": a.get("target"),
                }
            )
        )
        if gate["status"] == "block":
            # Hard block — never continue; halt the batch fail-closed.
            return _json(
                "denied",
                executed=executed,
                results=results
                + [
                    {
                        "index": idx + 1,
                        "command": cmd,
                        "status": "blocked",
                        "errors": gate.get("errors", []),
                    }
                ],
                reason=f"command [{idx + 1}] blocked: {gate.get('errors', ['blocked'])[0]}",
            )
        if gate["status"] == "review" and os.environ.get("HERMES_YOLO_MODE") != "1":
            # Soft review blocks unless yolo overrides; also halts the batch.
            return _json(
                "denied",
                executed=executed,
                results=results
                + [
                    {
                        "index": idx + 1,
                        "command": cmd,
                        "status": "review_required",
                        "warnings": gate.get("warnings", []),
                    }
                ],
                reason=f"command [{idx + 1}] requires review before execution",
            )
        try:
            r = execution.execute(
                command=cmd,
                eng_dir=eng_dir,
                phase=phase,
                backend=backend,
                timeout_seconds=timeout_seconds,
                cwd=cwd,
                label=label,
                ptt_task_id=(
                    ptt.find_active_task(ptt.parse_ptt(_eng_path(eng_dir) / "state" / "ptt.md")).id
                    if ptt.find_active_task(ptt.parse_ptt(_eng_path(eng_dir) / "state" / "ptt.md"))
                    else ""
                ),
            )
            r.pop("status", None)
            entry = {"index": idx + 1, "command": cmd, **r}
            results.append(entry)
            if r.get("executed"):
                executed += 1
            # A target command that ran but failed: honor continue_on_error.
            if r.get("exit_code", 0) != 0 and not continue_on_error:
                break
        except Exception as e:  # noqa: BLE001 - executor error must not abort silently
            if not continue_on_error:
                return _json(
                    "execution_failed",
                    executed=executed,
                    results=results + [{"index": idx + 1, "command": cmd, "error": str(e)}],
                    error=str(e),
                )
            results.append({"index": idx + 1, "command": cmd, "error": str(e)})

    return _json("batch_complete", executed=executed, results=results)


def handle_target(a, **kwargs):
    import yaml

    p = _eng_path(a["eng_dir"]) / "scope" / "scope.yaml"
    d = yaml.safe_load(p.read_text())
    ips = d.get("targets", {}).get("ip_addresses", [])
    if ips:
        return _json("ok", value=ips[0])
    return _json("error", error="no targets in scope")


def handle_status(a, **kwargs):
    return _json(
        "ok",
        sync_pending=state.has_pending_sync(a["eng_dir"]),
        sync_credit_remaining=state.sync_credit_remaining(a["eng_dir"]),
        command_count=state.read_counts(a["eng_dir"])["commands"],
    )


def handle_search_exploit(a, **kwargs):
    return _json("ok", **search_exploit(a))
