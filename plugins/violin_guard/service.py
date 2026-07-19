"""All tool handler implementations for the Violin Guard Hermes plugin."""

from __future__ import annotations

import hashlib
import json
import os
import re
import shlex
from functools import wraps
from pathlib import Path

from . import bootstrap, execution, findings, hypotheses, ptt, runtime_backend, state
from . import command as cmd_module
from .adapters import (
    build_ffuf,
    build_httpx,
    build_netcat_listener,
    build_nuclei,
    search_exploit,
)
from .command import CheckCommandArgs
from .history import history_contains
from .phases import Phase, requires_hypothesis, suppresses_heartbeat
from .skill_receipts import HermesSkillViewAdapter, bind_task, complete_delivery, prepare_delivery
from .targets import resolve_target

# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _eng_path(eng_dir: str) -> Path:
    return state.resolve_eng_dir(eng_dir)


def _json(status_name: str, **payload) -> str:
    payload.pop("status", None)
    return json.dumps({"schema_version": 2, "status": status_name, **payload})


def _result(r):
    return {"errors": r.errors, "warnings": r.warnings, "infos": r.infos}


def _check_command_internal(a) -> cmd_module.CheckResult:
    return cmd_module.check_command(
        CheckCommandArgs(
            command=a.get("command", ""),
            phase=a.get("phase", ""),
            eng_dir=a.get("eng_dir", ""),
            scope=a.get("scope", ""),
            target=a.get("target"),
            session_id=a.get("session_id"),
        )
    )


def _call(fn, args, **kwargs):
    """Wrap a handler function with uniform error serialisation."""
    try:
        return fn(args or {}, **kwargs)
    except Exception as exc:
        return _json("error", error=str(exc))


def _serialise_errors(fn):
    """Keep every model-visible handler on the stable JSON response contract."""

    @wraps(fn)
    def wrapped(args=None, **kwargs):
        return _call(fn, args, **kwargs)

    return wrapped


# ---------------------------------------------------------------------------
# Handler implementations
# ---------------------------------------------------------------------------


@_serialise_errors
def handle_check_command(a, **kwargs):
    r = _check_command_internal(a)
    status_name = "ok" if r.exit_code() == 0 else "review" if r.exit_code() == 2 else "block"
    return _json(status_name, **_result(r))


@_serialise_errors
def handle_record_ptt(a, **kwargs):
    eng_dir = a["eng_dir"]
    doc = ptt.parse_ptt(_eng_path(eng_dir) / "state" / "ptt.md")
    pending = state.get_pending_sync(eng_dir)
    task = a.get("id")
    note = (a.get("note") or "").strip()
    status = a.get("status", "[~]")
    skill = str(a.get("skill") or "").strip()
    technique = str(a.get("technique") or "").strip()

    if not task or not note:
        raise ValueError("task id and non-empty lifecycle note required")
    if not skill or not technique:
        raise ValueError("skill and technique are required before a PTT update")
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
        raise ValueError(f"hypothesis_id is required for {phase.value} PTT work")
    vulnerability_class = ""
    if hypothesis_id:
        normalized = hypothesis_id.removeprefix("H-").lstrip("0") or "0"
        matched = next(
            (
                h
                for h in hypotheses.parse_hypotheses(_eng_path(eng_dir) / "hypotheses.md")
                if h.id.lstrip("0") == normalized
            ),
            None,
        )
        vulnerability_class = matched.vuln_class if matched else ""
    digest = "sha256:" + hashlib.sha256(f"policy:{skill}".encode()).hexdigest()
    reservation = prepare_delivery(
        eng_dir,
        session_id=state.resolve_session_id(eng_dir) or "ptt",
        skill=skill,
        bundle_digest=digest,
        phase=phase.value,
        vulnerability_class=vulnerability_class or None,
    )
    if reservation.owner:
        viewed = HermesSkillViewAdapter().view(skill, task_id=task)
        completed = complete_delivery(eng_dir, reservation, viewed)
        return _json(
            "skill_prepared" if completed.status == "delivered" else "skill_unavailable",
            transition_applied=False,
            skill={
                "name": skill,
                "digest": digest,
                "content": viewed.content,
                "error": viewed.error,
            },
        )
    if reservation.status == "preparing":
        return _json(
            "skill_preparing", transition_applied=False, skill={"name": skill, "digest": digest}
        )
    binding = bind_task(
        eng_dir,
        task_id=task,
        delivery_id=reservation.id,
        hypothesis_id=hypothesis_id,
        technique=technique,
    )
    note = _with_skill_token(note, skill, digest)
    if not any(item.id == task for item in doc):
        created = ptt.create_task(
            _eng_path(eng_dir) / "state" / "ptt.md",
            task,
            a.get("title") or task,
            a.get("phase") or "RECON",
            note,
        )
        doc = ptt.parse_ptt(_eng_path(eng_dir) / "state" / "ptt.md")
        if status == "[ ]":
            return _json("ok", task_id=created.id, task_created=True)
    existing = next((item for item in doc if item.id == task), None)
    if existing and existing.status == "[~]" and status == "[~]":
        ptt.update_task(_eng_path(eng_dir) / "state" / "ptt.md", task, "[~]", note)
        return _json("ok", task_id=task, task_refreshed=True, binding=binding)
    if existing and status in {"[x]", "[-]"}:
        if existing.status != "[~]":
            raise ValueError("only the active [~] task may be closed outside a batch")
        ptt.update_task(_eng_path(eng_dir) / "state" / "ptt.md", task, status, note)
        return _json("ok", task_id=task, task_closed=True)
    return _start_ptt_task(_eng_path(eng_dir) / "state" / "ptt.md", doc, task, status, note)


def _with_skill_token(note: str, skill: str, digest: str) -> str:
    """Keep exactly one replaceable selection token in a PTT note."""
    token = f"[skill:{skill}@{digest}]"
    stripped = re.sub(r"\s*\[skill:[^\]]+\]", "", note).strip()
    return f"{stripped} {token}".strip()


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


@_serialise_errors
def handle_record_hypothesis(a, **kwargs):
    eng_dir = a["eng_dir"]
    fields = {k: v for k, v in a.items() if k != "eng_dir"}
    in_scope = _scope_hosts(eng_dir)
    h = hypotheses.update_hypothesis(
        _eng_path(eng_dir) / "hypotheses.md", in_scope_hosts=in_scope, **fields
    )
    return _json("ok", hypothesis=h.to_dict())


def _scope_hosts(eng_dir: str) -> set[str] | None:
    """Return the in-scope host set from scope.yaml, or None if no scope file."""
    import yaml

    from .targets import scope_hosts

    scope_path = _eng_path(eng_dir) / "scope" / "scope.yaml"
    if not scope_path.exists():
        return None
    try:
        data = yaml.safe_load(scope_path.read_text(encoding="utf-8")) or {}
    except Exception:
        return None
    return scope_hosts(data) or None


def _task_row_contains(path: Path, task_id: str, marker: str) -> bool:
    for line in path.read_text(encoding="utf-8").splitlines():
        match = re.match(r"^\|\s*(PT-[\w-]+)\s*\|", line.strip())
        if match and match.group(1) == task_id:
            return marker in line
    return False


def _validate_review_batch(a: dict, pending: dict) -> dict:
    eng_dir = str(a.get("eng_dir") or "")
    task_id = str(a.get("id") or "").strip()
    note = str(a.get("note") or "").strip()
    status = str(a.get("status") or "").strip()
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

    for item in pending.get("commands") or []:
        command = str(item.get("command") or "")
        if command and not history_contains(eng_dir, command):
            raise ValueError(
                f"pending command not yet in exact history: {command!r}; "
                "wait for execution completion before review"
            )

    finding = a.get("finding")
    if finding is not None:
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
        )
    return {
        "batch_id": batch_id,
        "task_id": task_id,
        "status": status,
        "note": note,
        "marker": marker,
        "already_recorded": already_recorded,
        "ptt_path": ptt_path,
        "finding": finding,
    }


@_serialise_errors
def handle_review_batch(a, **kwargs):
    """Review one completed batch, optionally record a finding, and release its lock."""

    eng_dir = str(a.get("eng_dir") or "").strip()
    if not eng_dir:
        raise ValueError("eng_dir is required")
    engagement = _eng_path(eng_dir)
    review_lock = engagement / "state" / "review-batch.json"
    try:
        with state.lock_file(review_lock):
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
            skill = str(a.get("skill") or "").strip()
            if skill:
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
                    phase=phase.value,
                )
                if reservation.owner:
                    viewed = HermesSkillViewAdapter().view(skill, task_id=task_id)
                    completed = complete_delivery(engagement, reservation, viewed)
                    return _json(
                        "skill_prepared"
                        if completed.status == "delivered"
                        else "skill_unavailable",
                        transition_applied=False,
                        released=False,
                        skill={
                            "name": skill,
                            "digest": digest,
                            "content": viewed.content,
                            "error": viewed.error,
                        },
                    )
                if reservation.status == "preparing":
                    return _json("skill_preparing", transition_applied=False, released=False)
                bind_task(
                    engagement,
                    task_id=task_id,
                    delivery_id=reservation.id,
                    hypothesis_id=hypothesis_id,
                    technique="batch-review",
                )
                a = {**a, "note": _with_skill_token(str(a.get("note") or ""), skill, digest)}
            context = _validate_review_batch(a, pending)
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
                )
            if not context["already_recorded"]:
                review_note = f"{context['note']} {context['marker']}"
                ptt.update_task(
                    context["ptt_path"], context["task_id"], context["status"], review_note
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
            )
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

    results = []
    executed = 0
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
                executed=executed,
                results=results
                + [
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
            )
            res.pop("status", None)
            entry = {"index": idx + 1, "command": cmd, **res}
            if review_warnings:
                entry["review_required"] = True
                entry["warnings"] = review_warnings
            results.append(entry)
            if res.get("executed"):
                executed += 1
            if res.get("exit_code", 0) != 0 and not continue_on_error:
                break
        except Exception as e:  # noqa: BLE001
            if not continue_on_error:
                return _json(
                    "execution_failed",
                    executed=executed,
                    results=results + [{"index": idx + 1, "command": cmd, "error": str(e)}],
                    error=str(e),
                )
            results.append({"index": idx + 1, "command": cmd, "error": str(e)})

    return _json(
        "batch_complete",
        executed=executed,
        results=results,
        review_required=any(item.get("review_required") for item in results),
    )


@_serialise_errors
def handle_target(a, **kwargs):
    """Resolve a target value from scope.yaml."""
    import yaml

    scope_path_arg = a.get("scope")
    p = Path(scope_path_arg) if scope_path_arg else _eng_path(a["eng_dir"]) / "scope" / "scope.yaml"

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
    skill_loaded = bool(marker and marker.is_file())

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
                "reason": "No session id is recorded for the skill-load gate",
                "next_action": "Load pentest, then create its marker for the current session",
            }
        )
    elif not skill_loaded:
        blockers.append(
            {
                "code": "skill_not_loaded",
                "reason": f"Pentest skill marker is missing for session {session_id}",
                "next_action": f"Load pentest, then create {marker}",
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
    if heartbeat_pending and not (current_phase and suppresses_heartbeat(Phase(current_phase))):
        blockers.append(
            {
                "code": "heartbeat_required",
                "reason": state.get_heartbeat_reason(eng_dir) or "Periodic review is pending",
                "next_action": "Review engagement state, then call violin_heartbeat_done",
            }
        )

    phase_requirements = {
        phase.value: {
            "ptt_phase": "EXPLOITATION" if phase is Phase.POST_EXPLOITATION else phase.value,
            "hypothesis_required": requires_hypothesis(phase),
            "sync_window": state.sync_credit_limit(phase.value),
            "heartbeat_enabled": not suppresses_heartbeat(phase),
        }
        for phase in Phase
    }
    pending_commands = [
        {"command": item.get("command", ""), "required_phase": item.get("phase", "")}
        for item in (pending or {}).get("commands") or []
    ]
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
        skill={
            "name": "pentest",
            "session_id": session_id or None,
            "loaded": skill_loaded,
            "marker": str(marker) if marker else None,
        },
        runtime=runtime_backend.runtime_readiness(eng_dir),
    )


@_serialise_errors
def handle_search_exploit(a, **kwargs):
    return _json("ok", **search_exploit(a))


# ---------------------------------------------------------------------------
# Adapter-built tool handlers (nmap, httpx, nuclei, ffuf, listener)
# ---------------------------------------------------------------------------


def _adapter(builder):
    """Create a handler that builds a command via ``builder`` then passes it to handle_exec."""

    def execute_adapter(args, **kwargs):
        values = args or {}
        built = builder(values)
        return _call(
            handle_exec,
            {
                **values,
                "target": values.get("target") or values.get("url"),
                "command": built,
                # Safe here because adapter builders quote every controlled value.
                "_argv": shlex.split(built, posix=True),
            },
        )

    return execute_adapter


handle_httpx = _adapter(build_httpx)
handle_nuclei = _adapter(build_nuclei)
handle_ffuf = _adapter(build_ffuf)


@_serialise_errors
def handle_listener(args, **kwargs):
    values = args or {}
    built = build_netcat_listener(values)
    return _call(
        handle_exec,
        {
            **values,
            "command": built,
            "_argv": shlex.split(built, posix=True),
            "background": True,
        },
    )


__all__ = [name for name in globals() if name.startswith("handle_")]
