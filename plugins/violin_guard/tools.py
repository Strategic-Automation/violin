"""Handlers for the violin-guard plugin. Each returns a JSON string.

All enforcement lives in the core guard CLI (``scripts/violin_guard.py``),
specifically the enforced ``check-command`` path plus the ``sync-done`` /
``heartbeat-done`` / ``message-tick`` subcommands. The plugin is a thin JSON
adapter over that CLI — no gate logic is duplicated here.
"""

from __future__ import annotations

import argparse
import json
import os
import tempfile
from pathlib import Path

from . import adapters, executor, utils


def _auto_approve() -> bool:
    """True when Hermes is running in yolo / auto-approve mode.

    Hermes exports ``HERMES_YOLO_MODE=1`` for ``--yolo`` / ``approvals.mode: off``.
    In that mode a guard REVIEW (exit 2, warnings only) must be treated as an
    approval, not a hold — the operator has already opted out of per-command
    approval. Genuine hard BLOCKs (exit 1: destructive patterns, out-of-scope
    targets, missing scope/bootstrap) are never auto-approved.
    """
    return os.environ.get("HERMES_YOLO_MODE") == "1"


_TARGET_TOUCHING = {"recon", "vuln-research", "exploitation", "post-exploitation"}


def _json(status: str, **payload) -> str:
    return json.dumps({"schema_version": 2, "status": status, **payload}, indent=2)


def _authorize(args: dict):
    return utils.run_guard(
        "check-command",
        scope=args.get("scope"),
        eng_dir=args.get("eng_dir"),
        phase=args.get("phase"),
        command=args.get("command"),
        session_id=args.get("session_id"),
        skill_loaded_file=args.get("skill_loaded_file"),
        defer_state=True,
    )


def handle_check_command(args: dict, **kwargs) -> str:
    res = utils.run_guard(
        "check-command",
        scope=args.get("scope"),
        eng_dir=args.get("eng_dir"),
        phase=args.get("phase"),
        command=args.get("command"),
        session_id=args.get("session_id"),
        skill_loaded_file=args.get("skill_loaded_file"),
    )
    parsed = utils.parse_exit(res)
    if res.returncode == 0:
        status = "ok"
    elif res.returncode == 2:
        # Under yolo/auto-approve, REVIEW (warnings only) is an approval.
        status = "ok" if _auto_approve() else "review"
    else:
        status = "block"
    return _json(status, **parsed)


def handle_record_ptt(args: dict, **kwargs) -> str:
    res = utils.run_guard(
        "record-ptt",
        eng_dir=args.get("eng_dir"),
        id=args.get("id"),
        status=args.get("status"),
        note=args.get("note"),
    )
    return _json(
        "ok" if res.returncode == 0 else "error",
        exit_code=res.returncode,
        raw=(res.stdout + res.stderr).strip(),
    )


def handle_record_hypothesis(args: dict, **kwargs) -> str:
    res = utils.run_hypothesis_guard(
        "record-hypothesis",
        eng_dir=args.get("eng_dir"),
        service=args.get("service"),
        port=args.get("port"),
        id=args.get("id"),
        title=args.get("title"),
        status=args.get("status"),
        phase=args.get("phase"),
        vuln_class=args.get("vuln_class"),
        rationale=args.get("rationale"),
        evidence=args.get("evidence"),
    )
    return _json(
        "ok" if res.returncode == 0 else "error",
        exit_code=res.returncode,
        raw=(res.stdout + res.stderr).strip(),
    )


def handle_record_history(args: dict, **kwargs) -> str:
    res = utils.run_guard(
        "record-history",
        eng_dir=args.get("eng_dir"),
        command=args.get("command"),
        exit_code=args.get("exit_code"),
        phase=args.get("phase"),
    )
    return _json(
        "ok" if res.returncode == 0 else "error",
        exit_code=res.returncode,
        raw=(res.stdout + res.stderr).strip(),
    )


def handle_exec(args: dict, **kwargs) -> str:
    """Forced-gate path. Runs the core-enforced ``check-command``.

    The core path performs the doc-sync gate, heartbeat gate, and stuck-loop
    guard, then the safety gate; it BLOCKs (exit 1) until artifacts are synced
    and any pending review is cleared. We just translate the CLI's exit code
    and BLOCK/REVIEW/OK lines into JSON for the tool caller.
    """
    res = _authorize(args)
    parsed = utils.parse_exit(res)

    # Check if blocked specifically due to pending doc-sync / exhausted sync-credit.
    sync_markers = (
        "prior command's artifacts not synced",
        "sync-credit window exhausted",
        "pending_command:",
    )
    if res.returncode == 1 and any(marker in (res.stdout or "") for marker in sync_markers):
        return _json(
            "sync_required",
            executed=False,
            command=args.get("command"),
            phase=args.get("phase"),
            review=parsed["review"],
            raw=parsed["raw"],
            hint="Stop target commands. Reconcile the pending command: state/history.md contains it, state/ptt.md Last updated is fresh, hypotheses.md Updated is fresh for vuln-research/exploitation; then call violin_sync_done.",
        )

    auto_approved = res.returncode == 2 and _auto_approve()
    if res.returncode in (0, 2) and (res.returncode == 0 or auto_approved):
        try:
            execution = executor.execute(
                args.get("command") or "",
                eng_dir=args.get("eng_dir") or "",
                phase=args.get("phase") or "",
                backend=args.get("backend", "local"),
                timeout_seconds=args.get("timeout_seconds", executor.DEFAULT_TIMEOUT),
                cwd=args.get("cwd", ""),
                label=args.get("label", ""),
                docker_container=os.environ.get("VIOLIN_DOCKER_CONTAINER", "kali-pentest"),
            )
        except Exception as exc:  # executor failures are not authorization blocks
            return _json(
                "execution_failed",
                executed=False,
                authorized=True,
                auto_approved=auto_approved,
                error=str(exc),
                review=parsed["review"],
            )
        execution_payload = {
            k: v for k, v in execution.items() if k not in {"schema_version", "status"}
        }
        return _json(
            "approved",
            authorized=True,
            auto_approved=auto_approved,
            execution_status=execution["status"],
            review=parsed["review"],
            **execution_payload,
        )
    if res.returncode == 2:
        return _json(
            "review",
            block=parsed["block"],
            review=parsed["review"],
            raw=parsed["raw"],
            executed=False,
            hint="Resolve REVIEW items (explicit approval) or call the required sync/heartbeat clear before re-running.",
        )
    return _json(
        "denied",
        block=parsed["block"],
        review=parsed["review"],
        raw=parsed["raw"],
        executed=False,
        hint="Resolve the BLOCK items, then re-call violin_exec.",
    )


def handle_heartbeat_done(args: dict, **kwargs) -> str:
    res = utils.run_guard("heartbeat-done", eng_dir=args.get("eng_dir"))
    return _json(
        "ok" if res.returncode in (0, 2) else "error", raw=(res.stdout + res.stderr).strip()
    )


def handle_message_tick(args: dict, **kwargs) -> str:
    res = utils.run_guard("message-tick", eng_dir=args.get("eng_dir"))
    return _json(
        "ok" if res.returncode == 0 else "review" if res.returncode == 2 else "error",
        raw=(res.stdout + res.stderr).strip(),
    )


def handle_sync_done(args: dict, **kwargs) -> str:
    res = utils.run_guard("sync-done", eng_dir=args.get("eng_dir"))
    return _json(
        "ok" if res.returncode == 0 else "review" if res.returncode == 2 else "error",
        raw=(res.stdout + res.stderr).strip(),
    )


def _inline_commands_file(commands: list[str]) -> str:
    """Materialize inline burst commands for the existing CLI boundary."""
    cleaned = [str(cmd).strip() for cmd in commands if str(cmd).strip()]
    if not cleaned:
        return ""
    fd, path = tempfile.mkstemp(prefix="violin-burst-", suffix=".txt")
    with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as f:
        f.write("\n".join(cleaned) + "\n")
    return path


def handle_exec_burst(args: dict, **kwargs) -> str:
    """Single-approval burst gate.

    The agent pre-approves a BATCH of target-touching commands. It may pass
    either ``commands_file`` (CLI-native) or inline ``commands``; inline
    commands are materialized to a temporary newline-delimited file before the
    core guard CLI runs. The guard checks every command and arms one sync lock.
    """
    commands_path = args.get("commands_file")
    temp_path = ""
    if not commands_path and args.get("commands"):
        temp_path = _inline_commands_file(args.get("commands") or [])
        commands_path = temp_path
    if not commands_path:
        return _json(
            "denied",
            raw="BLOCK: commands or commands_file is required",
            hint="Pass commands=[...] for a batch, or commands_file pointing to newline-delimited commands.",
        )
    try:
        commands = [
            line.strip()
            for line in Path(commands_path).read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        ]
        authorizations = []
        for command in commands:
            item = {**args, "command": command}
            res = _authorize(item)
            parsed = utils.parse_exit(res)
            if res.returncode == 1:
                return _json(
                    "denied",
                    executed=False,
                    command=command,
                    block=parsed["block"],
                    review=parsed["review"],
                    raw=parsed["raw"],
                )
            if res.returncode == 2 and not _auto_approve():
                return _json(
                    "review",
                    executed=False,
                    command=command,
                    review=parsed["review"],
                    raw=parsed["raw"],
                )
            authorizations.append((command, res.returncode == 2, parsed["review"]))
        results = []
        for command, auto_approved, review in authorizations:
            result = executor.execute(
                command,
                eng_dir=args.get("eng_dir") or "",
                phase=args.get("phase") or "",
                backend=args.get("backend", "local"),
                timeout_seconds=args.get("timeout_seconds", executor.DEFAULT_TIMEOUT),
                cwd=args.get("cwd", ""),
                label=args.get("label", "burst"),
                docker_container=os.environ.get("VIOLIN_DOCKER_CONTAINER", "kali-pentest"),
            )
            result["auto_approved"] = auto_approved
            result["review"] = review
            results.append(result)
            if result["exit_code"] != 0 and not args.get("continue_on_error", False):
                break
        return _json(
            "approved",
            executed=bool(results),
            results=results,
            sync_required=bool(results and results[-1]["sync_required"]),
            sync_credit_remaining=results[-1]["sync_credit_remaining"] if results else None,
        )
    except Exception as exc:
        return _json("execution_failed", executed=False, authorized=True, error=str(exc))
    finally:
        if temp_path:
            Path(temp_path).unlink(missing_ok=True)


def handle_exec_status(args: dict, **kwargs) -> str:
    try:
        return _json(
            "ok",
            execution=executor.status(args.get("eng_dir") or "", args.get("execution_id") or ""),
        )
    except Exception as exc:
        return _json("error", error=str(exc))


def handle_exec_cancel(args: dict, **kwargs) -> str:
    try:
        return _json(
            "ok",
            execution=executor.cancel(args.get("eng_dir") or "", args.get("execution_id") or ""),
        )
    except Exception as exc:
        return _json("error", error=str(exc))


def handle_search_exploit(args: dict, **kwargs) -> str:
    try:
        result = adapters.search_exploit(args)
        return _json("ok" if result["available"] else "unavailable", **result)
    except Exception as exc:
        return _json("error", error=str(exc), candidates=[], executed_candidates=False)


def _handle_adapter(tool: str, args: dict) -> str:
    backend = args.get("backend", "local")
    available, detail = adapters.available(
        tool, backend, os.environ.get("VIOLIN_DOCKER_CONTAINER", "kali-pentest")
    )
    if not available:
        return _json("unavailable", executed=False, tool=tool, detail=detail)
    try:
        command = adapters.BUILDERS[tool](args)
    except Exception as exc:
        return _json("error", executed=False, tool=tool, error=str(exc))
    return handle_exec({**args, "command": command, "label": args.get("label") or tool})


def handle_nmap(args: dict, **kwargs) -> str:
    return _handle_adapter("nmap", args)


def handle_httpx(args: dict, **kwargs) -> str:
    return _handle_adapter("httpx", args)


def handle_nuclei(args: dict, **kwargs) -> str:
    return _handle_adapter("nuclei", args)


def handle_ffuf(args: dict, **kwargs) -> str:
    return _handle_adapter("ffuf", args)


def handle_target(args: dict, **kwargs) -> str:
    """Resolve the canonical in-scope target from scope.yaml."""
    res = utils.run_guard(
        "target",
        eng_dir=args.get("eng_dir"),
        scope=args.get("scope"),
        host=args.get("host", ""),
        role=args.get("role", ""),
        field=args.get("field", "ip"),
    )
    return _json(
        "ok" if res.returncode == 0 else "error",
        target=(res.stdout or "").strip(),
        raw=(res.stdout + res.stderr).strip(),
    )


# --------------------------------------------------------------------------- #
# Consolidated status (replaces check-bootstrap + check-skill-loaded +
# sync-done + message-tick read calls with ONE call).
# --------------------------------------------------------------------------- #
def handle_status(args: dict, **kwargs) -> str:
    """One-shot engagement status: bootstrap, skill-load, sync, heartbeat.

    Replaces up to four separate read calls (violin_check_bootstrap,
    violin_check_skill_loaded, violin_sync_done, violin_message_tick) with a
    single consolidated read, so the agent can poll engagement health without
    burning four tool calls. Read-only — no state is mutated.
    """
    eng_dir_str = (
        args.get("eng_dir") or os.environ.get("ENG_DIR") or os.environ.get("VIOLIN_ENG_ROOT") or ""
    )
    eng_dir_str = str(eng_dir_str)

    # Bootstrap (pure variant, no stdout print).
    from guard.bootstrap import bootstrap_status

    boot = bootstrap_status(_status_args(eng_dir_str))
    # Skill-load gate (read-only presence check).
    # Default: discover the session-scoped marker like check-command does
    # (state/.skill-loaded-*); honour an explicit path if supplied.
    from guard.core import CheckResult

    skills_result = CheckResult()
    explicit = (args.get("skill_loaded_file") or "").strip()
    if explicit:
        skill_marker = Path(explicit)
    else:
        markers = list(Path(eng_dir_str).glob("state/.skill-loaded-*")) if eng_dir_str else []
        skill_marker = markers[0] if markers else None
    if skill_marker and skill_marker.is_file():
        skills_result.add_info(f"skill-load marker present: {skill_marker}")
    else:
        skills_result.add_warning(
            "skill load gate: no --skill-loaded-file/--session-id passed; SKILL.md load not verified"
        )

    # Sync / heartbeat state machine (read-only read functions).
    pending_sync = utils.has_pending_sync(eng_dir_str) if eng_dir_str else None
    heartbeat = utils.has_heartbeat_pending(eng_dir_str) if eng_dir_str else None
    sync_credit = utils.sync_credit_remaining(eng_dir_str) if eng_dir_str else 0
    counts = (
        utils.read_counts(eng_dir_str) if eng_dir_str else {"command_count": 0, "message_count": 0}
    )

    problems = (
        list(boot.errors)
        + list(boot.warnings)
        + list(skills_result.errors)
        + list(skills_result.warnings)
    )
    status = "ok" if not problems else "review"
    return _json(
        status,
        bootstrap={
            "ok": not (boot.errors or boot.warnings),
            "errors": boot.errors,
            "warnings": boot.warnings,
        },
        skill_loaded={
            "ok": not (skills_result.errors or skills_result.warnings),
            "errors": skills_result.errors,
            "warnings": skills_result.warnings,
        },
        pending_sync=pending_sync,
        heartbeat_pending=heartbeat,
        sync_credit_remaining=sync_credit,
        command_count=counts.get("command_count", 0),
        message_count=counts.get("message_count", 0),
        problems=problems,
    )


def _status_args(eng_dir_str: str):
    """Build a minimal argparse.Namespace for the pure bootstrap_status read."""
    ns = argparse.Namespace()
    ns.eng_dir = eng_dir_str
    ns.auto_repair = False
    return ns
