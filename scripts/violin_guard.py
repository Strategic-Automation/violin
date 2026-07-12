#!/usr/bin/env python3
"""Violin lightweight safety and release guard — CLI entrypoint.

The actual command implementations live in the `guard` package
(`scripts/guard/`). This module only owns argument parsing and dispatch, so
the guard logic stays in focused, individually-testable modules.

Exit codes:
  0 = allowed / valid
  1 = blocked / invalid
  2 = review or explicit approval required
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

# Make the scripts/ directory importable so `guard` and `hypothesis_guard` resolve,
# regardless of the caller's working directory.
SCRIPTS_DIR = Path(__file__).resolve().parent
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

from guard.bootstrap import check_bootstrap, check_skill_loaded, init_engagement  # noqa: E402
from guard.command import check_command  # noqa: E402
from guard.closeout import check_closeout  # noqa: E402
from guard.record import record_ptt, record_history, VALID_STATUSES  # noqa: E402
from guard.release import check_release  # noqa: E402
from guard.scope import validate_scope  # noqa: E402
# Single source of truth for the doc-sync + heartbeat + stuck-loop state machine.
from guard import sync as sync_state  # noqa: E402
# Single source of truth for the canonical engagement root + resolver. Every
# subcommand that takes --eng-dir now resolves through here so the skill and
# the plugin converge on the same absolute tree (root-cause fix).
from guard.core import ENG_ROOT, resolve_eng_dir  # noqa: E402

# Importable marker so the plugin and the CLI share identical enforcement logic.
__all__ = ["main", "check_command_enforced"]


def check_command_enforced(args: argparse.Namespace) -> int:
    """check-command WITH doc-sync / heartbeat / stuck-loop enforcement.

    This is the path the LLM must use for every target-touching command. It:

      1) BLOCKS if a prior approved command's artifacts (ptt.md / history.md /
         hypothesis-board.md) have not been synced yet (caller must run the
         command, update the artifacts, then call ``sync-done``).
      2) BLOCKS if a periodic coarse review (heartbeat) is pending — the LLM
         must re-read SKILL.md and review the engagement files, then call
         ``heartbeat-done``.
      3) Runs the normal safety gate (scope, skill-load, PTT/hypothesis
         freshness, dangerous/tier3 patterns). BLOCK => block.
      4) On allow: marks a pending-sync, ticks the command counter, and sets a
         heartbeat lock if the cadence interval was hit.

    The raw ``check_command`` function still exists for non-engagement /
    pre-bootstrap use; the enforced wrapper is what makes doc completion
    mandatory rather than advisory.
    """
    eng_dir = args.eng_dir or ""
    phase = (args.phase or "").lower()
    command = args.command or ""

    if eng_dir:
        # 1) doc-sync gate
        pending = sync_state.has_pending_sync(eng_dir)
        if pending is not None:
            print("BLOCK: prior command's artifacts not synced yet.")
            print(f"  pending_command: {pending.get('command')}")
            print("  ACTION: run the command, update ptt.md 'Last updated:' + state/history.md"
                  " (+ hypothesis-board.md 'Updated:' in vuln-research/exploitation), then call:"
                  " violin_guard.py sync-done --eng-dir \"$ENG_DIR\"")
            return 1
        # 2) heartbeat gate
        hb = sync_state.has_heartbeat_pending(eng_dir)
        if hb is not None:
            print("BLOCK: periodic engagement-file review (heartbeat) is pending.")
            print(f"  reason: {hb.get('reason')}")
            print("  ACTION: re-read skills/pentest/SKILL.md (drift guard + vuln playbooks),"
                  " review scope.yaml / ptt.md / hypotheses.md / history.md for drift, then call:"
                  " violin_guard.py heartbeat-done --eng-dir \"$ENG_DIR\"")
            return 1
        # Anti-stuck: re-issuing the exact same command past the limit is the
        # classic "stuck retrying" anti-pattern. Force research instead.
        if sync_state.repeat_count(eng_dir, command) >= sync_state.RETRY_LIMIT:
            print(f"BLOCK: command repeated {sync_state.RETRY_LIMIT}+ times without progress.")
            print("  ACTION: stop retrying. Record the observation as a hypothesis or note, run a"
                  " different command, or web_search / web_extract for the service's CVEs & exploits"
                  " before re-attempting. Document the change in ptt.md.")
            return 1

    # 3) safety gate
    rc = check_command(args)

    # 4) on allow/review, arm the next-call gates.
    # A REVIEW (rc=2) means "allowed but record this" (e.g. history-not-yet-
    # recorded) — the command still ran, so the LLM MUST sync its artifacts
    # before the next one. Only a hard BLOCK (rc=1) must NOT arm the gate.
    if rc in (0, 2) and eng_dir:
        sync_state.record_ok_check(eng_dir, command, phase)
        sync_state.mark_pending_sync(eng_dir, command, phase)
        count = sync_state.tick_command(eng_dir)
        if count % sync_state.COMMAND_INTERVAL == 0:
            sync_state.set_heartbeat_pending(
                eng_dir,
                f"Reached {count} approved target commands (interval {sync_state.COMMAND_INTERVAL})."
                " Review engagement files for drift before continuing.",
            )
    return rc


def cmd_check_closeout(args: argparse.Namespace) -> int:
    """Hard gate: verify mandatory REPORTING/RETROSPECTIVE artifacts exist.

    Returns exit 1 (denied — NOT auto-approved under --yolo) when a mandated
    artifact is missing for the given phase. Pass --command for the
    artifact-producing command so it is exempted (no deadlock).
    """
    res = check_closeout(args.eng_dir, args.phase, args.command or "")
    if res.errors or res.warnings:
        res.print()
    else:
        print("OK: close-out artifacts satisfied.")
    return res.exit_code()


def cmd_sync_done(args: argparse.Namespace) -> int:
    """Verify the prior command's artifacts are fresh; clear the sync lock."""
    eng_dir = args.eng_dir or ""
    pending = sync_state.has_pending_sync(eng_dir)
    if pending is None:
        print("OK: nothing pending — artifacts already in sync.")
        return 0
    if sync_state.artifacts_are_fresh(eng_dir, pending):
        sync_state.clear_pending_sync(eng_dir)
        print("OK: artifacts verified fresh. Next target command allowed.")
        return 0
    
    # Provide actionable guidance on what specifically is stale
    pending_ts = pending.get("ts", "")
    pending_cmd = pending.get("command", "")
    pending_phase = pending.get("phase", "")
    print("REVIEW: artifacts not yet updated to the prior command's timestamp.")
    print(f"  pending_command: {pending_cmd}")
    print(f"  pending_phase: {pending_phase}")
    print(f"  pending_ts: {pending_ts}")
    print()
    print("  ACTION REQUIRED: Update ALL of the following after running the command:")
    print("    1) ptt.md (state/ptt.md): Update the relevant PT-XXX row status AND")
    print("       bump the '*Last updated: YYYY-MM-DD HH:MM UTC*' footer")
    print("    2) history.md (state/history.md): record-history with the EXACT command string")
    print("    3) hypotheses.md (top-level, for vuln-research/exploitation phases):")
    print("       Update the 'Updated: YYYY-MM-DD HH:MM' field for active hypotheses")
    print()
    print("  Example workflow after running a command:")
    print("    python scripts/violin_guard.py record-history --eng-dir \"$ENG_DIR\" \\")
    print("      --command \"<exact command>\" --exit-code <N> --phase <PHASE>")
    print("    python scripts/violin_guard.py record-ptt --eng-dir \"$ENG_DIR\" \\")
    print("      --id PT-XXX --status \"[~]\" --note \"<result summary>\"")
    print("    python scripts/violin_guard.py sync-done --eng-dir \"$ENG_DIR\"")
    return 2


def cmd_sync_clear(args: argparse.Namespace) -> int:
    """Force-clear a pending-sync lock regardless of artifact freshness.

    Session-start reconciliation: a prior session may have approved a command,
    run it, recorded history, but exited before calling ``sync-done``. That
    leftover lock would otherwise BLOCK the first command of the new session
    (root-cause fix, issue 3). ``sync-clear`` drops it unconditionally.
    """
    eng_dir = args.eng_dir or ""
    cleared = sync_state.force_clear_pending_sync(eng_dir)
    if cleared:
        print("OK: pending-sync lock force-cleared.")
    else:
        print("OK: no pending-sync lock to clear.")
    return 0


def cmd_heartbeat_done(args: argparse.Namespace) -> int:
    """Clear the pending heartbeat review lock (LLM self-attests the review)."""
    eng_dir = args.eng_dir or ""
    hb = sync_state.has_heartbeat_pending(eng_dir)
    if hb is None:
        print("OK: no heartbeat review pending.")
        return 0
    sync_state.clear_heartbeat_pending(eng_dir)
    print("OK: heartbeat review cleared. Re-read of pentest SKILL.md and engagement-file"
          " review complete — target commands allowed.")
    return 0


def cmd_message_tick(args: argparse.Namespace) -> int:
    """LLM-opt-in: tick the message counter; set a heartbeat lock on interval."""
    eng_dir = args.eng_dir or ""
    count = sync_state.tick_message(eng_dir)
    if count % sync_state.MESSAGE_INTERVAL == 0:
        sync_state.set_heartbeat_pending(
            eng_dir,
            f"Reached {count} messages (interval {sync_state.MESSAGE_INTERVAL})."
            " Review engagement files for drift before continuing.",
        )
        print(f"OK: message_count={count}; heartbeat triggered — next command requires heartbeat-done.")
        return 2
    print(f"OK: message_count={count}.")
    return 0


def cmd_eng_root(args: argparse.Namespace) -> int:
    """Print the canonical engagement root and resolve an eng_dir to absolute.

    The skill/scoping bootstrap calls this to obtain an ABSOLUTE ENG_DIR that
    the violin-guard plugin will resolve identically. When --eng-dir is given, prints the
    resolved absolute path; otherwise prints just ENG_ROOT.
    """
    if args.eng_dir:
        resolved = resolve_eng_dir(args.eng_dir)
        print(f"ENG_ROOT={ENG_ROOT}")
        print(f"ENG_DIR={resolved}")
    else:
        print(f"ENG_ROOT={ENG_ROOT}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Violin lightweight safety and release guard")
    subparsers = parser.add_subparsers(dest="command_name", required=True)

    scope_parser = subparsers.add_parser("validate-scope", help="validate an engagement scope file")
    scope_parser.add_argument("--scope", required=True)
    scope_parser.set_defaults(func=validate_scope)

    command_parser = subparsers.add_parser("check-command", help="check a target-touching terminal command (enforced: blocks until prior artifacts synced + periodic review done)")
    command_parser.add_argument("--scope", required=True)
    command_parser.add_argument("--phase", required=True)
    command_parser.add_argument("--command", required=True)
    command_parser.add_argument("--eng-dir", default="", help="engagement directory; enables doc-sync/heartbeat/stuck-loop enforcement")
    command_parser.add_argument("--skill-loaded-file", default="", help="skill-load marker path; when set, missing marker blocks the command")
    command_parser.add_argument("--session-id", default="", help="current session or goal label; when set, --skill-loaded-file must encode the same session id")
    command_parser.set_defaults(func=check_command_enforced)

    closeout_parser = subparsers.add_parser(
        "check-closeout",
        help="hard gate: verify mandatory REPORTING/RETROSPECTIVE artifacts exist "
             "(report.md, retrospective.md, phase-summary.md, CVSS:3.1, Research Log). "
             "Missing artifacts BLOCK even under --yolo.",
    )
    closeout_parser.add_argument("--eng-dir", required=True, help="engagement directory")
    closeout_parser.add_argument("--phase", required=True, help="REPORTING or RETROSPECTIVE")
    closeout_parser.add_argument("--command", default="", help="artifact-producing command (exempts the gate)")
    closeout_parser.set_defaults(func=cmd_check_closeout)

    sync_parser = subparsers.add_parser("sync-done", help="call AFTER updating ptt.md/history.md/hypothesis-board.md for the last approved command; verifies freshness and unlocks the next command")
    sync_parser.add_argument("--eng-dir", required=True, help="engagement directory")
    sync_parser.set_defaults(func=cmd_sync_done)

    sync_clear_parser = subparsers.add_parser(
        "sync-clear",
        help="force-clear a stale pending-sync lock (use at session start to drop a "
             "leftover lock from a prior session that died before sync-done)",
    )
    sync_clear_parser.add_argument("--eng-dir", required=True, help="engagement directory")
    sync_clear_parser.set_defaults(func=cmd_sync_clear)

    heartbeat_parser = subparsers.add_parser("heartbeat-done", help="call AFTER re-reading SKILL.md + reviewing engagement files on the cadence; clears the heartbeat lock")
    heartbeat_parser.add_argument("--eng-dir", required=True, help="engagement directory")
    heartbeat_parser.set_defaults(func=cmd_heartbeat_done)

    tick_parser = subparsers.add_parser("message-tick", help="LLM-opt-in: call once per assistant message; sets a heartbeat lock every MESSAGE_INTERVAL messages")
    tick_parser.add_argument("--eng-dir", required=True, help="engagement directory")
    tick_parser.set_defaults(func=cmd_message_tick)

    eng_root_parser = subparsers.add_parser(
        "eng-root",
        help="print the canonical engagement root (ENG_ROOT) and resolve a given "
             "engagement directory to its absolute path under it; used by the "
             "skill/scoping bootstrap to build an ABSOLUTE ENG_DIR that matches "
             "the plugin (root-cause fix for divergent engagement trees)",
    )
    eng_root_parser.add_argument(
        "--eng-dir", default="",
        help="optional engagement dir to resolve (e.g. '10.129.46.56-2026-07-08' "
             "or 'engagements/10.129.46.56-2026-07-08'); if omitted, prints ENG_ROOT",
    )
    eng_root_parser.set_defaults(func=cmd_eng_root)

    bootstrap_parser = subparsers.add_parser("check-bootstrap", help="verify engagement bootstrap is complete (scope, PTT, hypothesis board, history exist)")
    bootstrap_parser.add_argument("--eng-dir", default="", help="engagement directory (ENG_DIR); pass explicitly or export as env var")
    bootstrap_parser.add_argument("--auto-repair", action="store_true", help="if a required bootstrap artifact is a directory (LLM bootstrap drift), remove it and re-create from the canonical template")
    bootstrap_parser.set_defaults(func=check_bootstrap)

    init_parser = subparsers.add_parser("init-engagement", help="auto-create a complete, guard-clean engagement directory from templates")
    init_parser.add_argument("--eng-dir", required=True, help="engagement directory to create (name should contain the host, e.g. engagements/10.129.45.228-2026-07-08)")
    init_parser.add_argument("--host", default="", help="target host/IP to pre-fill in scope.yaml; if omitted, derived from --eng-dir name")
    init_parser.set_defaults(func=lambda a: init_engagement(a.eng_dir, host=a.host))

    release_parser = subparsers.add_parser("check-release", help="validate release readiness")
    release_parser.set_defaults(func=check_release)

    ptt_parser = subparsers.add_parser("record-ptt", help="update a PT-XXX row in the PTT")
    ptt_parser.add_argument("--eng-dir", required=True, help="engagement directory")
    ptt_parser.add_argument("--id", required=True, help="PT-XXX id (e.g. PT-016)")
    ptt_parser.add_argument("--status", required=True, choices=sorted(VALID_STATUSES), help="new status marker")
    ptt_parser.add_argument("--note", default="", help="one-line note appended to Evidence column")
    ptt_parser.set_defaults(func=record_ptt)

    skill_parser = subparsers.add_parser("check-skill-loaded", help="mark SKILL.md as read for the current session/work-block")
    skill_parser.add_argument("--eng-dir", required=True, help="engagement directory")
    skill_parser.add_argument("--session-id", required=True, help="session or goal label, used in marker filename")
    skill_parser.add_argument("--skill-loaded-file", default="", help="write marker to explicit path; default: $ENG_DIR/state/.skill-loaded-<session-id>")
    skill_parser.set_defaults(func=check_skill_loaded)

    history_parser = subparsers.add_parser("record-history", help="append a timestamped entry to history.md")
    history_parser.add_argument("--eng-dir", required=True, help="engagement directory")
    history_parser.add_argument("--command", required=True, help="shell command that was just run")
    history_parser.add_argument("--exit-code", required=True, type=int, help="exit code of the command")
    history_parser.add_argument("--phase", default="UNKNOWN", help="phase tag (default: UNKNOWN)")
    history_parser.add_argument("--evidence", default="", help="evidence path under $ENG_DIR/evidence/")
    history_parser.set_defaults(func=record_history)

    args = parser.parse_args()

    # ROOT-CAUSE FIX (issue 1): resolve every --eng-dir through a single source
    # of truth so the skill's relative "engagements/..." form and an absolute
    # path both land on the same canonical tree under ENG_ROOT. Subcommands that
    # take --eng-dir read args.eng_dir AFTER this point.
    if getattr(args, "eng_dir", None):
        args.eng_dir = resolve_eng_dir(args.eng_dir)

    try:
        return args.func(args)
    except Exception as exc:  # noqa: BLE001 - CLI should fail clearly
        print(f"BLOCK: {exc}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
