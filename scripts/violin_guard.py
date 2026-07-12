#!/usr/bin/env python3
"""CLI entry point for violin_guard — delegates to plugins/violin_guard/core/."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

# Bootstrap plugin core path - add the parent of the plugin directory
_PROFILE_ROOT = Path(__file__).resolve().parent.parent
if str(_PROFILE_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROFILE_ROOT))

from plugins.violin_guard.core import bootstrap, command, state
from plugins.violin_guard.core.phases import normalize_phase


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
        session_id=args.session_id or "",
        skill_loaded_file=args.skill_loaded_file or "",
    )
    result = command.check_command(cmd_args)
    return _print_result(result)


def cmd_check_bootstrap(args: argparse.Namespace) -> int:
    result = bootstrap.check_bootstrap(args.eng_dir, auto_repair=args.auto_repair)
    return _print_result(result)


def cmd_init_engagement(args: argparse.Namespace) -> int:
    return bootstrap.init_engagement(args.eng_dir, host=args.host)


def cmd_check_skill_loaded(args: argparse.Namespace) -> int:
    result = command.check_skill_load(Path(args.eng_dir), args.session_id, mandatory=True)
    return _print_result(result)


def cmd_record_history(args: argparse.Namespace) -> int:
    state.append_history(args.eng_dir, args.command, args.phase, args.exit_code, args.evidence)
    print("OK: history recorded")
    return 0


def cmd_record_ptt(args: argparse.Namespace) -> int:
    from plugins.violin_guard.core import ptt

    ptt.update_task(
        Path(args.eng_dir) / "state" / "ptt.md",
        args.id,
        args.status,
        args.note or "",
    )
    print(f"OK: PTT {args.id} updated")
    return 0


def cmd_sync_done(args: argparse.Namespace) -> int:
    from plugins.violin_guard.core.service import handle_sync_done
    out=json.loads(handle_sync_done(vars(args))); print(out); return 0 if out["status"]=="ok" else 1


def cmd_heartbeat_done(args: argparse.Namespace) -> int:
    state.clear_heartbeat_pending(args.eng_dir)
    print("OK: heartbeat cleared")
    return 0


def cmd_message_tick(args: argparse.Namespace) -> int:
    """Handle message tick - increment counter and check heartbeat gate."""
    from plugins.violin_guard.core.state import (
        tick_message,
        has_heartbeat_pending,
        get_heartbeat_reason,
    )

    eng_dir = args.eng_dir
    count = tick_message(eng_dir)

    # Check if heartbeat is already pending (from previous tick)
    if has_heartbeat_pending(eng_dir):
        reason = get_heartbeat_reason(eng_dir)
        print(f"BLOCK: heartbeat pending: {reason}")
        return 1  # BLOCK

    # Check if heartbeat should be triggered now (every MESSAGE_INTERVAL messages)
    if count % 30 == 0:
        from plugins.violin_guard.core.state import set_heartbeat_pending
        set_heartbeat_pending(
            eng_dir,
            f"Reached {count} LLM messages. Review engagement files for drift.",
        )
        print("BLOCK: heartbeat triggered")
        return 1  # BLOCK

    print("OK: message tick")
    return 0


def cmd_eng_root(args: argparse.Namespace) -> int:
    from plugins.violin_guard.core import state

    eng_root = state._eng_dir(args.eng_dir) if args.eng_dir else state._eng_dir("")
    print(f"ENG_ROOT={eng_root}")
    if args.eng_dir:
        resolved = state._eng_dir(args.eng_dir)
        print(f"resolved={resolved}")
    return 0

def cmd_check_release(args) -> int:
    from plugins.violin_guard.core.release import check_release
    result = check_release()
    for item in result.errors: print(f"ERROR: {item}")
    for item in result.warnings: print(f"WARN: {item}")
    for item in result.infos: print(f"OK: {item}")
    return result.exit_code()


def main() -> int:
    parser = argparse.ArgumentParser(prog="violin_guard.py")
    sub = parser.add_subparsers(dest="cmd", required=True)

    # check-command
    p = sub.add_parser("check-command", help="Run all pre-execution guards")
    p.add_argument("--command", required=True)
    p.add_argument("--phase", required=True)
    p.add_argument("--eng-dir", required=True)
    p.add_argument("--scope", required=True)
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
    p.set_defaults(func=cmd_eng_root)

    p = sub.add_parser("check-release", help="Run release checks")
    p.set_defaults(func=cmd_check_release)

    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
