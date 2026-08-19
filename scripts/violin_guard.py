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

from plugins.violin_guard import handlers
from plugins.violin_guard.core import bootstrap, findings, state
from plugins.violin_guard.engine import release
from plugins.violin_guard.gates import command


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


def cmd_generate_closeout(args: argparse.Namespace) -> int:
    try:
        yaml_path = findings.generate_findings_yaml(args.eng_dir, force=args.force)
        report_path = findings.generate_report_md(
            args.eng_dir, target=args.target, force=args.force
        )
    except ValueError as exc:
        print(f"BLOCK: {exc}")
        return 1
    print(f"OK: wrote {yaml_path}")
    print(f"OK: wrote {report_path}")
    return 0


def cmd_record_ptt(args: argparse.Namespace) -> int:
    out = json.loads(
        handlers.handle_record_ptt(
            {
                "eng_dir": args.eng_dir,
                "id": args.id,
                "status": args.status,
                "note": args.note or "",
                "skill": args.skill,
                "technique": args.technique,
                "hypothesis_id": args.hypothesis_id,
                "phase": args.phase,
            }
        )
    )
    print(out)
    return 0 if out["status"] == "ok" else 1


def cmd_review_batch(args: argparse.Namespace) -> int:
    finding = None
    finding_values = {
        "finding_id": args.finding_id,
        "title": args.finding_title,
        "severity": args.finding_severity,
        "description": args.finding_description,
        "impact": args.finding_impact,
        "remediation": args.finding_remediation,
    }
    if any(str(value or "").strip() for value in finding_values.values()):
        finding = finding_values
    out = json.loads(
        handlers.handle_review_batch(
            {
                "eng_dir": args.eng_dir,
                "id": args.id,
                "status": args.status,
                "note": args.note,
                "skill": args.skill,
                "hypothesis_id": args.hypothesis_id,
                "technique": args.technique,
                "finding": finding,
            }
        )
    )
    print(json.dumps(out, indent=2))
    return 0 if out["status"] == "ok" else 1


def cmd_rebind_pending_batch(args: argparse.Namespace) -> int:
    out = json.loads(
        handlers.handle_rebind_pending_batch(
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


def cmd_status(args: argparse.Namespace) -> int:
    out = json.loads(handlers.handle_status({"eng_dir": args.eng_dir}))
    if args.section == "skill":
        skill = out.get("skill", {})
        print(json.dumps(skill, indent=2))
        return 0 if skill.get("binding_ready") else 1
    print(json.dumps(out, indent=2))
    return 0 if out["status"] == "ok" else 1


def cmd_eng_root(args: argparse.Namespace) -> int:
    eng_dir = args.eng_dir_option or args.eng_dir
    eng_root = state._eng_root()
    print(f"ENG_ROOT={eng_root}")
    if eng_dir:
        resolved = state.resolve_eng_dir(eng_dir)
        print(f"resolved={resolved}")
    return 0


def cmd_check_release(args) -> int:
    return release.main()


def cmd_target(args: argparse.Namespace) -> int:
    out = json.loads(
        handlers.handle_target(
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
    out = json.loads(
        handlers.handle_exec_burst(
            {
                "eng_dir": args.eng_dir,
                "scope": args.scope,
                "phase": args.phase,
                "target": args.target or "",
                "commands": [],
                "commands_file": args.commands_file or "",
                "session_id": args.session_id or "",
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
        "--session-id",
        default="",
        help="Record the Hermes session ID for receipt-backed CTF bootstrap",
    )
    p.set_defaults(func=cmd_init_engagement)

    # record-ptt
    p = sub.add_parser("record-ptt", help="Update PTT task status")
    p.add_argument("--eng-dir", required=True)
    p.add_argument("--id", required=True)
    p.add_argument("--status", required=True)
    p.add_argument("--note", default="")
    p.add_argument("--skill", required=True)
    p.add_argument("--technique", required=True)
    p.add_argument("--hypothesis-id", default="")
    p.add_argument("--phase", default="")
    p.set_defaults(func=cmd_record_ptt)

    p = sub.add_parser(
        "review-batch", help="Review a completed batch, optionally record a finding, and unlock"
    )
    p.add_argument("--eng-dir", required=True)
    p.add_argument("--id", required=True)
    p.add_argument("--status", required=True, choices=["[~]", "[x]", "[!]", "[-]"])
    p.add_argument("--note", required=True)
    p.add_argument("--skill", default="")
    p.add_argument("--hypothesis-id", default="")
    p.add_argument("--technique", default="")
    p.add_argument("--finding-id", default="")
    p.add_argument("--finding-title", default="")
    p.add_argument(
        "--finding-severity", default="", choices=["", "Critical", "High", "Medium", "Low", "Info"]
    )
    p.add_argument("--finding-description", default="")
    p.add_argument("--finding-impact", default="")
    p.add_argument("--finding-remediation", default="")
    p.set_defaults(func=cmd_review_batch)

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

    p = sub.add_parser("status", help="Explain current phase, task, blockers, and next actions")
    p.add_argument("--eng-dir", required=True)
    p.add_argument("--section", choices=["all", "skill"], default="all")
    p.set_defaults(func=cmd_status)

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

    p = sub.add_parser(
        "generate-closeout",
        help="Derive findings.yaml and report.md from canonical FIND-*.md files",
    )
    p.add_argument("--eng-dir", required=True)
    p.add_argument("--target", required=True)
    p.add_argument("--force", action="store_true", help="Overwrite existing artifacts")
    p.set_defaults(func=cmd_generate_closeout)

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
    p.add_argument("--label", default="")
    p.add_argument("--continue-on-error", action="store_true")
    p.set_defaults(func=cmd_exec_burst)

    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
