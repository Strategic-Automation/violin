#!/usr/bin/env python3
"""CLI entry point for violin_guard — delegates to plugins/violin_guard/."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

# Bootstrap the profile root so the plugin package can be imported directly.
_PROFILE_ROOT = Path(__file__).resolve().parent.parent
if str(_PROFILE_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROFILE_ROOT))

from plugins.violin_guard import bootstrap, command, state


def _print_result(result) -> int:
    if hasattr(result, "print"):
        result.print()
    return result.exit_code()


def cmd_check_command(args: argparse.Namespace) -> int:
    cmd_args = command.CheckCommandArgs(
        command=args.command,
        phase=args.phase,
        eng_dir=args.eng_dir,
        scope=args.scope,
        target=args.target or None,
        session_id=args.session_id or "",
        skill_loaded_file=args.skill_loaded_file or "",
    )
    result = command.check_command(cmd_args)
    return _print_result(result)


def cmd_check_bootstrap(args: argparse.Namespace) -> int:
    result = bootstrap.check_bootstrap(args.eng_dir, auto_repair=args.auto_repair)
    return _print_result(result)


def cmd_init_engagement(args: argparse.Namespace) -> int:
    return bootstrap.init_engagement(
        args.eng_dir, host=args.host, ctf=args.ctf, session_id=args.session_id
    )


def cmd_validate_scope(args: argparse.Namespace) -> int:
    result = command.validate_scope(Path(args.scope))
    code = result.exit_code()
    label = "OK" if code == 0 else "REVIEW" if code == 2 else "BLOCK"
    messages = result.errors or result.warnings or result.infos or ["scope valid"]
    print(f"{label}: {messages[0]}")
    return code


def cmd_check_skill_loaded(args: argparse.Namespace) -> int:
    result = command.check_skill_load(
        state.resolve_eng_dir(args.eng_dir), args.session_id, mandatory=True
    )
    return _print_result(result)


def cmd_record_history(args: argparse.Namespace) -> int:
    from plugins.violin_guard import history

    history.append_history(args.eng_dir, args.command, args.phase, args.exit_code, args.evidence)
    print("OK: history recorded")
    return 0


def cmd_record_ptt(args: argparse.Namespace) -> int:
    from plugins.violin_guard import ptt

    ptt.update_task(
        state.resolve_eng_dir(args.eng_dir) / "state" / "ptt.md",
        args.id,
        args.status,
        args.note or "",
    )
    print(f"OK: PTT {args.id} updated")
    return 0


def cmd_sync_done(args: argparse.Namespace) -> int:
    from plugins.violin_guard import service

    out = json.loads(service.handle_sync_done(vars(args)))
    print(out)
    return 0 if out["status"] == "ok" else 1


def cmd_rebind_pending_batch(args: argparse.Namespace) -> int:
    from plugins.violin_guard import service

    out = json.loads(
        service.handle_rebind_pending_batch(
            {
                "eng_dir": args.eng_dir,
                "batch_id": args.batch_id,
                "current_task_id": args.current_task_id,
                "replacement_task_id": args.replacement_task_id,
                "note": args.note,
                "confirm": args.confirm,
            }
        )
    )
    print(out)
    return 0 if out["status"] == "ok" else 1


def cmd_heartbeat_done(args: argparse.Namespace) -> int:
    state.clear_heartbeat_pending(args.eng_dir)
    print("OK: heartbeat cleared")
    return 0


def cmd_message_tick(args: argparse.Namespace) -> int:
    """Handle message tick - increment counter and check heartbeat gate."""

    eng_dir = args.eng_dir
    count = state.tick_message(eng_dir)

    # Check if heartbeat is already pending (from previous tick)
    if state.has_heartbeat_pending(eng_dir):
        reason = state.get_heartbeat_reason(eng_dir)
        print(f"BLOCK: heartbeat pending: {reason}")
        return 1  # BLOCK

    # Check if heartbeat should be triggered now (every MESSAGE_INTERVAL messages)
    if count % state.MESSAGE_INTERVAL == 0:
        state.set_heartbeat_pending(
            eng_dir,
            f"Reached {count} LLM messages. Review engagement files for drift.",
        )
        print("BLOCK: heartbeat triggered")
        return 1  # BLOCK

    print("OK: message tick")
    return 0


def cmd_eng_root(args: argparse.Namespace) -> int:
    from plugins.violin_guard import state

    eng_dir = args.eng_dir_option or args.eng_dir
    eng_root = state._eng_root()
    print(f"ENG_ROOT={eng_root}")
    if eng_dir:
        resolved = state.resolve_eng_dir(eng_dir)
        print(f"resolved={resolved}")
    return 0


def cmd_check_release(args) -> int:
    from plugins.violin_guard import release

    result = release.check_release()
    for item in result.errors:
        print(f"ERROR: {item}")
    for item in result.warnings:
        print(f"WARN: {item}")
    for item in result.infos:
        print(f"OK: {item}")
    return result.exit_code()


def cmd_search_exploit(args: argparse.Namespace) -> int:
    from plugins.violin_guard import adapters

    result = adapters.search_exploit(
        {
            "product": args.product,
            "version": args.version,
            "service": args.service,
            "cve": args.cve,
        }
    )
    print(json.dumps(result, indent=2))
    return 0 if result.get("available") else 1


def cmd_target(args: argparse.Namespace) -> int:
    from plugins.violin_guard import service

    out = json.loads(
        service.handle_target(
            {
                "eng_dir": args.eng_dir,
                "scope": args.scope or "",
                "host": args.host or "",
                "role": args.role or "",
                "field": args.field or "ip",
            }
        )
    )
    if out.get("status") != "ok":
        print(out.get("error", "target resolution failed"))
        return 1
    print(out.get("value", ""))
    return 0


def cmd_exec_burst(args: argparse.Namespace) -> int:
    from plugins.violin_guard import service

    out = json.loads(
        service.handle_exec_burst(
            {
                "eng_dir": args.eng_dir,
                "scope": args.scope,
                "phase": args.phase,
                "target": args.target or "",
                "commands": [],
                "commands_file": args.commands_file or "",
                "session_id": args.session_id or "",
                "skill_loaded_file": args.skill_loaded_file or "",
                "label": args.label or "",
                "continue_on_error": args.continue_on_error,
            }
        )
    )
    status = out.get("status")
    if status == "denied":
        print("BURST VERDICT: DENIED")
    else:
        print(f"BURST VERDICT: {status.upper()}")
    for r in out.get("results", []):
        idx = r.get("index", "?")
        cmd = r.get("command", "")
        print(f"[{idx}] {cmd}")
    return 0 if status not in ("denied", "error", "execution_failed") else 1


def main() -> int:
    parser = argparse.ArgumentParser(prog="violin_guard.py")
    sub = parser.add_subparsers(dest="cmd", required=True)

    # check-command
    p = sub.add_parser("check-command", help="Run all pre-execution guards")
    p.add_argument("--command", required=True)
    p.add_argument("--phase", required=True)
    p.add_argument("--eng-dir", required=True)
    p.add_argument("--scope", default="", help="defaults to <eng-dir>/scope/scope.yaml")
    p.add_argument("--target", default="", help="Explicit primary target host/IP/URL")
    p.add_argument("--session-id", default="")
    p.add_argument("--skill-loaded-file", default="")
    p.set_defaults(func=cmd_check_command)

    # check-bootstrap
    p = sub.add_parser("check-bootstrap", help="Verify engagement bootstrap")
    p.add_argument("--eng-dir", required=True)
    p.add_argument("--auto-repair", action="store_true")
    p.set_defaults(func=cmd_check_bootstrap)

    # init-engagement
    p = sub.add_parser("init-engagement", help="Create guard-clean engagement")
    p.add_argument("eng_dir")
    p.add_argument("--host", default="")
    p.add_argument("--ctf", action="store_true", help="Create an HTB/CTF-ready scope and PTT")
    p.add_argument(
        "--session-id", default="", help="Mark this session skill-loaded for CTF bootstrap"
    )
    p.set_defaults(func=cmd_init_engagement)

    # check-skill-loaded
    p = sub.add_parser("check-skill-loaded", help="Mark skill as loaded for session")
    p.add_argument("--eng-dir", required=True)
    p.add_argument("--session-id", required=True)
    p.set_defaults(func=cmd_check_skill_loaded)

    # record-history
    p = sub.add_parser("record-history", help="Append command to history.md")
    p.add_argument("--eng-dir", required=True)
    p.add_argument("--command", required=True)
    p.add_argument("--exit-code", type=int, required=True)
    p.add_argument("--phase", required=True)
    p.add_argument("--evidence", default="")
    p.set_defaults(func=cmd_record_history)

    # record-ptt
    p = sub.add_parser("record-ptt", help="Update PTT task status")
    p.add_argument("--eng-dir", required=True)
    p.add_argument("--id", required=True)
    p.add_argument("--status", required=True)
    p.add_argument("--note", default="")
    p.set_defaults(func=cmd_record_ptt)

    # sync-done
    p = sub.add_parser("sync-done", help="Clear pending sync lock")
    p.add_argument("--eng-dir", required=True)
    p.set_defaults(func=cmd_sync_done)

    p = sub.add_parser("rebind-pending-batch", help="Explicitly rebind a completed pending batch")
    p.add_argument("--eng-dir", required=True)
    p.add_argument("--batch-id", required=True)
    p.add_argument("--current-task-id", required=True)
    p.add_argument("--replacement-task-id", required=True)
    p.add_argument("--note", required=True)
    p.add_argument("--confirm", action="store_true")
    p.set_defaults(func=cmd_rebind_pending_batch)

    # heartbeat-done
    p = sub.add_parser("heartbeat-done", help="Clear heartbeat pending")
    p.add_argument("--eng-dir", required=True)
    p.set_defaults(func=cmd_heartbeat_done)

    # message-tick
    p = sub.add_parser("message-tick", help="Increment message counter")
    p.add_argument("--eng-dir", required=True)
    p.set_defaults(func=cmd_message_tick)

    # eng-root
    p = sub.add_parser("eng-root", help="Print canonical engagement root")
    p.add_argument("eng_dir", nargs="?")
    p.add_argument("--eng-dir", dest="eng_dir_option")
    p.set_defaults(func=cmd_eng_root)

    p = sub.add_parser("validate-scope", help="Validate scope.yaml")
    p.add_argument("--scope", required=True)
    p.set_defaults(func=cmd_validate_scope)

    p = sub.add_parser("check-release", help="Run release checks")
    p.set_defaults(func=cmd_check_release)

    # search-exploit
    p = sub.add_parser("search-exploit", help="Search local ExploitDB (read-only)")
    p.add_argument("--product", default="")
    p.add_argument("--version", default="")
    p.add_argument("--service", default="")
    p.add_argument("--cve", default="")
    p.set_defaults(func=cmd_search_exploit)

    # target
    p = sub.add_parser("target", help="Resolve in-scope target from scope.yaml")
    p.add_argument("--eng-dir", required=True)
    p.add_argument("--scope", default="")
    p.add_argument("--host", default="")
    p.add_argument("--role", default="")
    p.add_argument("--field", default="ip", choices=["ip", "url", "host"])
    p.set_defaults(func=cmd_target)

    # exec-burst
    p = sub.add_parser("exec-burst", help="Single-approval bounded command batch")
    p.add_argument("--eng-dir", required=True)
    p.add_argument("--scope", default="", help="defaults to <eng-dir>/scope/scope.yaml")
    p.add_argument("--phase", required=True)
    p.add_argument("--target", required=True, help="Explicit primary target for the batch")
    p.add_argument("--commands-file", default="")
    p.add_argument("--session-id", default="")
    p.add_argument("--skill-loaded-file", default="")
    p.add_argument("--label", default="")
    p.add_argument("--continue-on-error", action="store_true")
    p.set_defaults(func=cmd_exec_burst)

    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
