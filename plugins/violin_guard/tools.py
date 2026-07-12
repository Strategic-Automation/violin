"""Handlers for the violin-guard plugin. Each returns a JSON string.

All enforcement lives in the core guard CLI (``scripts/violin_guard.py``),
specifically the enforced ``check-command`` path plus the ``sync-done`` /
``heartbeat-done`` / ``message-tick`` subcommands. The plugin is a thin JSON
adapter over that CLI — no gate logic is duplicated here.
"""
from __future__ import annotations

import json
import os
from . import utils


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
    return json.dumps({"status": status, **payload}, indent=2)


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
    res = utils.run_guard("record-ptt", eng_dir=args.get("eng_dir"),
                          id=args.get("id"), status=args.get("status"),
                          note=args.get("note"))
    return _json("ok" if res.returncode == 0 else "error",
                 exit_code=res.returncode, raw=(res.stdout + res.stderr).strip())


def handle_record_hypothesis(args: dict, **kwargs) -> str:
    res = utils.run_hypothesis_guard("record-hypothesis", eng_dir=args.get("eng_dir"),
                                     service=args.get("service"), port=args.get("port"),
                                     id=args.get("id"), title=args.get("title"),
                                     status=args.get("status"), phase=args.get("phase"),
                                     vuln_class=args.get("vuln_class"),
                                     rationale=args.get("rationale"),
                                     evidence=args.get("evidence"))
    return _json("ok" if res.returncode == 0 else "error",
                 exit_code=res.returncode, raw=(res.stdout + res.stderr).strip())


def handle_record_history(args: dict, **kwargs) -> str:
    res = utils.run_guard("record-history", eng_dir=args.get("eng_dir"),
                          command=args.get("command"),
                          exit_code=args.get("exit_code"),
                          phase=args.get("phase"))
    return _json("ok" if res.returncode == 0 else "error",
                 exit_code=res.returncode, raw=(res.stdout + res.stderr).strip())


def handle_exec(args: dict, **kwargs) -> str:
    """Forced-gate path. Runs the core-enforced ``check-command``.

    The core path performs the doc-sync gate, heartbeat gate, and stuck-loop
    guard, then the safety gate; it BLOCKs (exit 1) until artifacts are synced
    and any pending review is cleared. We just translate the CLI's exit code
    and BLOCK/REVIEW/OK lines into JSON for the tool caller.
    """
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
    
    # Check if blocked specifically due to pending doc-sync
    if res.returncode == 1 and any("prior command's artifacts not synced" in line for line in (res.stdout or "").splitlines()):
        return _json("sync_required", command=args.get("command"), phase=args.get("phase"),
                     review=parsed["review"], raw=parsed["raw"],
                     hint="Run the command, update ptt.md 'Last updated:' + state/history.md (+ hypotheses.md 'Updated:' in vuln-research/exploitation), then call violin_sync_done.")
    
    if res.returncode == 0:
        return _json("approved", command=args.get("command"), phase=args.get("phase"),
                     review=parsed["review"], note=parsed["raw"])
    if res.returncode == 2:
        if _auto_approve():
            # yolo/auto-approve: warnings-only REVIEW is an approval, so the
            # command can actually run instead of being held in a review loop.
            return _json("approved", command=args.get("command"), phase=args.get("phase"),
                         review=parsed["review"],
                         note="auto-approved under yolo/auto-approve mode (REVIEW items bypassed)")
        return _json("review", block=parsed["block"], review=parsed["review"],
                     raw=parsed["raw"],
                     hint="Resolve REVIEW items (explicit approval) or call the required sync/heartbeat clear before re-running.")
    return _json("denied", block=parsed["block"], review=parsed["review"], raw=parsed["raw"],
                 hint="Resolve the BLOCK items, then re-call violin_exec.")


def handle_heartbeat_done(args: dict, **kwargs) -> str:
    res = utils.run_guard("heartbeat-done", eng_dir=args.get("eng_dir"))
    return _json("ok" if res.returncode in (0, 2) else "error", raw=(res.stdout + res.stderr).strip())


def handle_message_tick(args: dict, **kwargs) -> str:
    res = utils.run_guard("message-tick", eng_dir=args.get("eng_dir"))
    return _json("ok" if res.returncode == 0 else "review" if res.returncode == 2 else "error",
                 raw=(res.stdout + res.stderr).strip())


def handle_sync_done(args: dict, **kwargs) -> str:
    res = utils.run_guard("sync-done", eng_dir=args.get("eng_dir"))
    return _json("ok" if res.returncode == 0 else "review" if res.returncode == 2 else "error",
                 raw=(res.stdout + res.stderr).strip())
