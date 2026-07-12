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

# Single source of truth for the doc-sync + heartbeat + stuck-loop state machine.
from guard import sync as sync_state  # noqa: E402
from guard.bootstrap import check_bootstrap, check_skill_loaded, init_engagement  # noqa: E402
from guard.closeout import check_closeout  # noqa: E402
from guard.command import _check_command_core, add_hosts, check_command, cleanup_hosts  # noqa: E402

# Single source of truth for the canonical engagement root + resolver. Every
# subcommand that takes --eng-dir now resolves through here so the skill and
# the plugin converge on the same absolute tree (root-cause fix).
from guard.core import (  # noqa: E402
    ENG_ROOT,
    LOCAL_TOOLS,
    as_list,
    command_leading_tool,
    load_yaml,
    resolve_eng_dir,
)
from guard.phase_gate import (  # noqa: E402
    check_all_phase_gates,
    check_phase_gate,
    closure_requested_from_ptt,
    normalize_phase,
)
from guard.record import VALID_STATUSES, record_history, record_ptt  # noqa: E402
from guard.release import check_release  # noqa: E402
from guard.scope import validate_scope  # noqa: E402

# Importable marker so the plugin and the CLI share identical enforcement logic.
__all__ = ["main", "check_command_enforced"]


def check_command_enforced(args: argparse.Namespace) -> int:
    """check-command WITH doc-sync / heartbeat / stuck-loop enforcement.

    This is the path the LLM must use for every target-touching command. It:

      1) DOC-SYNC WINDOW GATE (issue 1, redesigned). The old design armed a
         pending-sync lock after EVERY approved command, forcing
         record-history + record-ptt + sync-done (3 tool calls) before the
         NEXT command — iterating 5-6 payload variants blew the ~50-call
         budget. Now each approved target command *spends one sync-credit* from
         a sliding window; the gate only BLOCKS once the credit is exhausted
         (default 5 commands). The agent runs a batch of N<=5 commands, records
         artifacts ONCE at batch end, then calls sync-done a single time.
      2) HEARTBEAT GATE (issue 2). Suppressed during EXPLOITATION /
         POST_EXPLOITATION (payload iteration must not be interrupted); the
         cadence is raised (COMMAND_INTERVAL 20 / MESSAGE_INTERVAL 30). When the
         gate fires, the LLM must re-read SKILL.md + review engagement files,
         then call ``heartbeat-done``.
      3) STUCK-LOOP GATE. Re-issuing the exact same command past RETRY_LIMIT is
         the classic "stuck retrying" anti-pattern.
      4) Runs the normal safety gate (scope, skill-load, PTT/hypothesis
         freshness, dangerous/tier3 patterns). BLOCK => block.
      5) On allow: spends a sync-credit, ticks the command counter, arms the
         pending-sync lock (single reconcile after the batch), and sets a
         heartbeat lock if the (raised) cadence interval was hit.

    The raw ``check_command`` function still exists for non-engagement /
    pre-bootstrap use; the enforced wrapper is what makes doc completion
    mandatory rather than advisory.
    """
    eng_dir = args.eng_dir or ""
    phase = (args.phase or "").lower()
    command = args.command or ""

    if eng_dir:
        # 1) DOC-SYNC WINDOW GATE (issue 1)
        pending = sync_state.has_pending_sync(eng_dir)
        if pending is not None:
            credits = sync_state.sync_credit_remaining(eng_dir)
            if credits <= 0:
                print(
                    f"BLOCK: sync-credit window exhausted ({sync_state.DEFAULT_SYNC_CREDIT} "
                    f"batched commands approved without an artifact sync)."
                )
                print(f"  pending_command: {pending.get('command')}")
                print(
                    "  ACTION: run the command, update ptt.md 'Last updated:' + state/history.md"
                    " (+ hypotheses.md 'Updated:' in vuln-research/exploitation), then call:"
                    ' violin_guard.py sync-done --eng-dir "$ENG_DIR"'
                )
                return 1
            # Window still open: allow, but remind the agent to reconcile at batch end.
            print(
                f"OK: sync-credit window open ({credits} command(s) remaining before required sync-done)."
            )
        # 2) HEARTBEAT GATE (issue 2) — suppressed during exploitation/post-exploitation
        if not sync_state.heartbeat_suppressed(phase):
            hb = sync_state.has_heartbeat_pending(eng_dir)
            if hb is not None:
                print("BLOCK: periodic engagement-file review (heartbeat) is pending.")
                print(f"  reason: {hb.get('reason')}")
                print(
                    "  ACTION: re-read skills/pentest/SKILL.md (drift guard + vuln playbooks),"
                    " review scope.yaml / ptt.md / hypotheses.md / history.md for drift, then call:"
                    ' violin_guard.py heartbeat-done --eng-dir "$ENG_DIR"'
                )
                return 1
        # 3) ANTI-STUCK
        if sync_state.repeat_count(eng_dir, command) >= sync_state.RETRY_LIMIT:
            print(f"BLOCK: command repeated {sync_state.RETRY_LIMIT}+ times without progress.")
            print(
                "  ACTION: stop retrying. Record the observation as a hypothesis or note, run a"
                " different command, or web_search / web_extract for the service's CVEs & exploits"
                " before re-attempting. Document the change in ptt.md."
            )
            return 1

    # 4) safety gate
    rc = check_command(args)

    # 5) on allow/review, spend a credit and arm the next-call gates.
    # A REVIEW (rc=2) means "allowed but record this" — the command still ran,
    # so the LLM MUST sync its artifacts before the window's end. Only a hard
    # BLOCK (rc=1) must NOT spend a credit or arm the gate.
    # Local interpreters / shell built-ins (cd, python3, ls, ...) are NOT
    # target-touching even if a host-shaped token appears in their arguments,
    # so they are exempt and never spend a credit (see core.LOCAL_TOOLS).
    from guard.core import command_leading_tool

    is_target = rc in (0, 2) and eng_dir and command_leading_tool(command) not in LOCAL_TOOLS
    if is_target and not getattr(args, "defer_state", False):
        sync_state.record_ok_check(eng_dir, command, phase)
        sync_state.spend_sync_credit(eng_dir)
        sync_state.mark_pending_sync(eng_dir, command, phase)
        count = sync_state.tick_command(eng_dir)
        if count % sync_state.COMMAND_INTERVAL == 0 and not sync_state.heartbeat_suppressed(phase):
            sync_state.set_heartbeat_pending(
                eng_dir,
                f"Reached {count} approved target commands (interval {sync_state.COMMAND_INTERVAL})."
                " Review engagement files for drift before continuing.",
            )
    return rc


def run_burst(
    commands: list[str],
    *,
    eng_dir: str = "",
    phase: str = "",
    scope: str = "",
    session_id: str = "",
    skill_loaded_file: str = "",
    label: str = "",
) -> dict:
    """Single-approval burst executor.

    The performance problem: the enforced ``check-command`` gate stamps a
    pending-sync lock after EVERY approved command, so the next command is
    BLOCKED until the operator runs it, rewrites ptt.md / history.md /
    hypothesis-board.md, then calls ``sync-done``. For a 5–20 step race
    (e.g. React2Shell / view-state deserialisation), that per-command
    sync tax blows the exploitation window or forces the operator to drop to
    the raw terminal (losing all guard coverage).

    Burst mode keeps FULL guard coverage but amortises the sync tax: every
    command is gated by the full safety gate (scope, skill-load,
    PTT/hypothesis freshness, dangerous/tier3 patterns, out-of-scope host
    rejection) — but the pending-sync / heartbeat / stuck-loop gates are
    deferred for the whole batch. Only the LAST command arms the normal
    per-command gates, so a single ``sync-done`` after the batch unlocks
    the next call.

    Returns a structured dict:
      verdict: "approved" | "review" | "denied"
      label:   the batch label (for the operator's log)
      n:       total commands
      approved: per-command passes  [(i, command, verdict)]
      blocked: earliest blocking command [(i, command, errors)]
      scope_hits: commands that touch in-scope hosts (proven target-touching)
    """
    results: list[tuple[int, str, str, list[str]]] = []
    scope_hits: list[str] = []
    # Pre-load scope once so we can report which commands actually touch an
    # in-scope host (proves the batch is genuinely target-touching, not noise).
    scope_data = load_yaml(Path(scope)) if scope else {}

    for i, command in enumerate(commands):
        cargs = argparse.Namespace(
            scope=scope,
            phase=phase,
            command=command,
            eng_dir=eng_dir,
            skill_loaded_file=skill_loaded_file,
            session_id=session_id,
        )
        res = _check_command_core(cargs)
        # REVIEW (rc=2, warnings only) is allowed with explicit approval;
        # BLOCK (errors) hard-stops the batch.
        if res.errors:
            verdict = "denied"
        elif res.warnings:
            verdict = "review"
        else:
            verdict = "approved"
        results.append((i, command, verdict, res.errors[:]))

        # Track in-scope-host touches for the operator's evidence log.
        if scope_data:
            from guard.command import extract_hosts, is_excluded_host, is_scoped_host

            for host in extract_hosts(command):
                if (
                    is_scoped_host(host, scope_data)
                    and not is_excluded_host(host, scope_data)
                    and command not in scope_hits
                ):
                    scope_hits.append(command)

        if verdict == "denied":
            # Hard block: stop the batch immediately (fail-closed).
            break

    # Aggregate verdict: any denial => denied; any review => review; else approved.
    if any(v == "denied" for _, _, v, _ in results):
        verdict = "denied"
    elif any(v == "review" for _, _, v, _ in results):
        verdict = "review"
    else:
        verdict = "approved"

    # Only the LAST command arms the normal per-command gates, so a single
    # sync-done after the batch unlocks the next call. Local tools / non-target
    # commands never arm the gates.
    if verdict in ("approved", "review") and eng_dir and commands:
        last = commands[-1]
        is_target = command_leading_tool(last) not in LOCAL_TOOLS
        if is_target:
            sync_state.record_ok_check(eng_dir, last, phase)
            sync_state.mark_pending_sync(eng_dir, last, phase)
            count = sync_state.tick_command(eng_dir)
            if count % sync_state.COMMAND_INTERVAL == 0 and not sync_state.heartbeat_suppressed(
                phase
            ):
                sync_state.set_heartbeat_pending(
                    eng_dir,
                    f"Reached {count} approved target commands (interval "
                    f"{sync_state.COMMAND_INTERVAL}). Review engagement files "
                    f"for drift before continuing.",
                )

    blocked = [(i, c, e) for (i, c, v, e) in results if v == "denied"]
    passed = [(i, c, v) for (i, c, v, _) in results if v != "denied"]
    return {
        "verdict": verdict,
        "label": label or "burst",
        "n": len(commands),
        "approved": passed,
        "blocked": blocked,
        "scope_hits": scope_hits,
    }


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


def cmd_check_phase_gate(args: argparse.Namespace) -> int:
    """Review whether one phase has all mandatory completion artifacts."""
    phase = normalize_phase(args.phase)
    ok, missing = check_phase_gate(args.eng_dir, phase)
    if ok:
        print(f"OK: phase gate passed for {phase}")
        return 0
    print(f"REVIEW: phase gate not satisfied for {phase}")
    for item in missing:
        print(f"  MISSING: {item}")
    return 1


def _print_closure_review(eng_dir: str) -> bool:
    """Print cumulative phase gaps; return True when closure is allowed."""
    failed = check_all_phase_gates(eng_dir)
    if not failed:
        return True
    print("REVIEW: engagement closure blocked — missing required artifacts:")
    for phase, missing in failed:
        print(f"  {phase}: {', '.join(missing)}")
    return False


def cmd_close(args: argparse.Namespace) -> int:
    """Allow closure only after every phase-completion gate passes."""
    if not _print_closure_review(args.eng_dir):
        return 1
    print("OK: all phase gates passed — engagement may be closed.")
    return 0


def cmd_sync_done(args: argparse.Namespace) -> int:
    """Verify freshness and refuse closure while phase artifacts are missing."""
    eng_dir = args.eng_dir or ""
    closure_requested = getattr(args, "close", False) or closure_requested_from_ptt(eng_dir)
    pending = sync_state.has_pending_sync(eng_dir)
    if pending is None:
        if closure_requested and not _print_closure_review(eng_dir):
            return 2
        print("OK: nothing pending — artifacts already in sync.")
        return 0
    if sync_state.artifacts_are_fresh(eng_dir, pending):
        if closure_requested and not _print_closure_review(eng_dir):
            # Keep the lock: closure was claimed while deliverables are absent.
            return 2
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
    print('    python scripts/violin_guard.py record-history --eng-dir "$ENG_DIR" \\')
    print('      --command "<exact command>" --exit-code <N> --phase <PHASE>')
    print('    python scripts/violin_guard.py record-ptt --eng-dir "$ENG_DIR" \\')
    print('      --id PT-XXX --status "[~]" --note "<result summary>"')
    print('    python scripts/violin_guard.py sync-done --eng-dir "$ENG_DIR"')
    return 2


def cmd_exec_burst(args: argparse.Namespace) -> int:
    """CLI wrapper for the single-approval burst executor.

    Reads a newline-delimited list of PRE-APPROVED-as-a-batch commands from
    ``--commands-file``, runs the full safety gate over each, and prints one
    aggregate verdict. The operator approves the BATCH (not each command), so
    the per-command doc-sync tax is amortised to a single ``sync-done``.
    """
    path = Path(args.commands_file)
    if not path.exists():
        print(f"BLOCK: commands file not found: {path}")
        return 1
    commands = [
        ln.strip()
        for ln in path.read_text(encoding="utf-8").splitlines()
        if ln.strip() and not ln.strip().startswith("#")
    ]
    if not commands:
        print(f"BLOCK: commands file is empty: {path}")
        return 1
    result = run_burst(
        commands,
        eng_dir=args.eng_dir or "",
        phase=args.phase,
        scope=args.scope,
        session_id=args.session_id or "",
        skill_loaded_file=args.skill_loaded_file or "",
        label=args.label or "",
    )
    verdict = result["verdict"]
    print(f"BURST VERDICT: {verdict.upper()}  (label={result['label']}, n={result['n']})")
    if result["scope_hits"]:
        print(f"  target-touching commands ({len(result['scope_hits'])}):")
        for c in result["scope_hits"]:
            print(f"    - {c}")
    if result["blocked"]:
        print("  BLOCKED commands:")
        for i, c, errs in result["blocked"]:
            print(f"    [{i}] {c}")
            for e in errs:
                print(f"        ! {e}")
        print("\nBLOCK: batch halted at first hard BLOCK. Fix the flagged command and re-submit.")
        return 1
    if verdict == "review":
        print("  REVIEW: some commands carry warnings (Tier-3 / PRIVESC-review).")
        print("  Approve the batch explicitly, then run the commands and call sync-done once.")
        return 2
    print(f"  APPROVED: run all {result['n']} commands, then call sync-done ONCE to unlock.")
    return 0


def cmd_target(args: argparse.Namespace) -> int:
    """Resolve the canonical in-scope target for the current engagement.

    Kills hardcoded-IP fragility: the agent asks for the target by role
    (``--role web`` or ``--host <ip/cidr>``), and the guard returns the
    authoritative value from ``scope.yaml`` — so a box reset / IP change
    requires editing ONE file, not grepping the whole history.

    Examples:
      violin_target --eng-dir "$ENG_DIR" --host 10.10.10.10 --field ip
        -> 10.10.10.10
      violin_target --eng-dir "$ENG_DIR" --role web --field url
        -> http://10.10.10.10
    """
    eng_dir = args.eng_dir or ""
    if not eng_dir:
        print("BLOCK: --eng-dir is required (target resolution is engagement-scoped)")
        return 1
    scope_path = (
        Path(args.scope)
        if getattr(args, "scope", None)
        else (Path(resolve_eng_dir(eng_dir)) / "scope" / "scope.yaml")
    )
    if not scope_path.exists():
        print(f"BLOCK: scope.yaml not found: {scope_path}")
        return 1
    scope = load_yaml(scope_path)
    if scope is None:
        print("BLOCK: scope.yaml failed to parse")
        return 1

    # Select the target record by host or role.
    targets = as_list((scope.get("targets") or {}).get("ip_addresses")) or []
    urls = as_list((scope.get("targets") or {}).get("in_scope_urls")) or []
    roles = (
        scope.get("targets", {}).get("roles", {}) if isinstance(scope.get("targets"), dict) else {}
    )

    chosen_ip = None
    if args.host:
        want = args.host.strip()
        if want in targets or any(want in str(t) for t in targets):
            chosen_ip = want
        else:
            print(f"BLOCK: host {want} is not in scope per {scope_path}")
            return 1
    elif args.role:
        role_ip = roles.get(args.role)
        if role_ip:
            chosen_ip = role_ip
        elif args.role == "web" and urls:
            print(urls[0])
            return 0
        else:
            print(f"BLOCK: no target for role={args.role} in scope.yaml")
            return 1
    else:
        # Default: first in-scope IP (single-target engagements).
        chosen_ip = targets[0] if targets else None

    if chosen_ip is None:
        print("BLOCK: no in-scope target resolved (check scope.yaml targets)")
        return 1

    # Emit the requested field.
    field = (args.field or "ip").lower()
    if field == "ip":
        print(chosen_ip)
    elif field == "url":
        # Prefer a matching in-scope URL, else synthesise http://ip.
        for u in urls:
            if chosen_ip in str(u):
                print(u)
                break
        else:
            print(f"http://{chosen_ip}")
    elif field == "host":
        print(chosen_ip)
    else:
        print(f"BLOCK: unknown --field {args.field} (use ip|url|host)")
        return 1
    return 0


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
    print(
        "OK: heartbeat review cleared. Re-read of pentest SKILL.md and engagement-file"
        " review complete — target commands allowed."
    )
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
        print(
            f"OK: message_count={count}; heartbeat triggered — next command requires heartbeat-done."
        )
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

    command_parser = subparsers.add_parser(
        "check-command",
        help="check a target-touching terminal command (enforced: blocks until prior artifacts synced + periodic review done)",
    )
    command_parser.add_argument("--scope", required=True)
    command_parser.add_argument("--phase", required=True)
    command_parser.add_argument("--command", required=True)
    command_parser.add_argument(
        "--eng-dir",
        default="",
        help="engagement directory; enables doc-sync/heartbeat/stuck-loop enforcement",
    )
    command_parser.add_argument(
        "--skill-loaded-file",
        default="",
        help="skill-load marker path; when set, missing marker blocks the command",
    )
    command_parser.add_argument(
        "--session-id",
        default="",
        help="current session or goal label; when set, --skill-loaded-file must encode the same session id",
    )
    command_parser.add_argument(
        "--defer-state",
        action="store_true",
        help=argparse.SUPPRESS,
    )
    command_parser.set_defaults(func=check_command_enforced)

    burst_parser = subparsers.add_parser(
        "exec-burst",
        help="single-approval burst gate: pre-check N target-touching commands "
        "at once (full safety gate each), deferring the doc-sync lock to "
        "the LAST command so one sync-done unlocks the next call. Drops "
        "the per-command sync tax that blows race-exploit windows.",
    )
    burst_parser.add_argument("--scope", required=True)
    burst_parser.add_argument("--phase", required=True)
    burst_parser.add_argument(
        "--commands-file",
        required=True,
        help="newline-delimited file of commands (that are PRE-APPROVED as a batch by the operator)",
    )
    burst_parser.add_argument(
        "--eng-dir",
        default="",
        help="engagement directory; enables one-time sync-lock arming on the last command",
    )
    burst_parser.add_argument("--skill-loaded-file", default="")
    burst_parser.add_argument("--session-id", default="")
    burst_parser.add_argument("--label", default="", help="optional batch label for logging")
    burst_parser.set_defaults(func=cmd_exec_burst)
    target_parser = subparsers.add_parser(
        "target",
        help="resolve the canonical in-scope target for the engagement from "
        "scope.yaml (by --host or --role), killing hardcoded-IP fragility "
        "(box resets just edit scope.yaml, not every command in history)",
    )
    target_parser.add_argument("--eng-dir", default="")
    target_parser.add_argument(
        "--scope", default="", help="explicit scope.yaml path (else $ENG_DIR/scope/scope.yaml)"
    )
    target_parser.add_argument("--host", default="", help="in-scope IP/CIDR to resolve")
    target_parser.add_argument(
        "--role", default="", help="named role from scope.yaml targets.roles (e.g. web)"
    )
    target_parser.add_argument(
        "--field", default="ip", choices=["ip", "url", "host"], help="what to print (default: ip)"
    )
    target_parser.set_defaults(func=cmd_target)

    closeout_parser = subparsers.add_parser(
        "check-closeout",
        help="hard gate: verify mandatory REPORTING/RETROSPECTIVE artifacts exist "
        "(report.md, retrospective.md, phase-summary.md, CVSS:3.1, Research Log). "
        "Missing artifacts BLOCK even under --yolo.",
    )
    closeout_parser.add_argument("--eng-dir", required=True, help="engagement directory")
    closeout_parser.add_argument("--phase", required=True, help="REPORTING or RETROSPECTIVE")
    closeout_parser.add_argument(
        "--command", default="", help="artifact-producing command (exempts the gate)"
    )
    closeout_parser.set_defaults(func=cmd_check_closeout)

    phase_gate_parser = subparsers.add_parser(
        "check-phase-gate",
        help="review whether a phase's mandatory completion artifacts exist",
    )
    phase_gate_parser.add_argument("--eng-dir", required=True, help="engagement directory")
    phase_gate_parser.add_argument("--phase", required=True, help="phase to verify")
    phase_gate_parser.set_defaults(func=cmd_check_phase_gate)

    close_parser = subparsers.add_parser(
        "close",
        help="gate engagement closure on every phase's mandatory deliverables",
    )
    close_parser.add_argument("--eng-dir", required=True, help="engagement directory")
    close_parser.set_defaults(func=cmd_close)

    sync_parser = subparsers.add_parser(
        "sync-done",
        help="call AFTER updating state/ptt.md/state/history.md/hypotheses.md for the last approved command; verifies freshness and unlocks the next command",
    )
    sync_parser.add_argument("--eng-dir", required=True, help="engagement directory")
    sync_parser.add_argument(
        "--close",
        action="store_true",
        help="explicitly request cumulative engagement-closure verification",
    )
    sync_parser.set_defaults(func=cmd_sync_done)

    sync_clear_parser = subparsers.add_parser(
        "sync-clear",
        help="force-clear a stale pending-sync lock (use at session start to drop a "
        "leftover lock from a prior session that died before sync-done)",
    )
    sync_clear_parser.add_argument("--eng-dir", required=True, help="engagement directory")
    sync_clear_parser.set_defaults(func=cmd_sync_clear)

    heartbeat_parser = subparsers.add_parser(
        "heartbeat-done",
        help="call AFTER re-reading SKILL.md + reviewing engagement files on the cadence; clears the heartbeat lock",
    )
    heartbeat_parser.add_argument("--eng-dir", required=True, help="engagement directory")
    heartbeat_parser.set_defaults(func=cmd_heartbeat_done)

    tick_parser = subparsers.add_parser(
        "message-tick",
        help="LLM-opt-in: call once per assistant message; sets a heartbeat lock every MESSAGE_INTERVAL messages",
    )
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
        "--eng-dir",
        default="",
        help="optional engagement dir to resolve (e.g. '10.129.46.56-2026-07-08' "
        "or 'engagements/10.129.46.56-2026-07-08'); if omitted, prints ENG_ROOT",
    )
    eng_root_parser.set_defaults(func=cmd_eng_root)

    bootstrap_parser = subparsers.add_parser(
        "check-bootstrap",
        help="verify engagement bootstrap is complete (scope, PTT, hypothesis board, history exist)",
    )
    bootstrap_parser.add_argument(
        "--eng-dir",
        default="",
        help="engagement directory (ENG_DIR); pass explicitly or export as env var",
    )
    bootstrap_parser.add_argument(
        "--auto-repair",
        action="store_true",
        help="if a required bootstrap artifact is a directory (LLM bootstrap drift), remove it and re-create from the canonical template",
    )
    bootstrap_parser.set_defaults(func=check_bootstrap)

    init_parser = subparsers.add_parser(
        "init-engagement",
        help="auto-create a complete, guard-clean engagement directory from templates",
    )
    init_parser.add_argument(
        "--eng-dir",
        required=True,
        help="engagement directory to create (name should contain the host, e.g. engagements/10.129.45.228-2026-07-08)",
    )
    init_parser.add_argument(
        "--host",
        default="",
        help="target host/IP to pre-fill in scope.yaml; if omitted, derived from --eng-dir name",
    )
    init_parser.set_defaults(func=lambda a: init_engagement(a.eng_dir, host=a.host))

    release_parser = subparsers.add_parser("check-release", help="validate release readiness")
    release_parser.set_defaults(func=check_release)

    ptt_parser = subparsers.add_parser(
        "record-ptt", help="update or create a PT-XXX row in the PTT"
    )
    ptt_parser.add_argument("--eng-dir", required=True, help="engagement directory")
    ptt_parser.add_argument("--id", required=True, help="PT-XXX id (e.g. PT-016)")
    ptt_parser.add_argument(
        "--status",
        required=False,
        default=None,
        choices=sorted(VALID_STATUSES) + [None],
        help="new status marker; required for status-update mode, "
        "optional in --create mode (defaults to [ ])",
    )
    ptt_parser.add_argument("--note", default="", help="one-line note appended to Evidence column")
    ptt_parser.add_argument(
        "--create",
        action="store_true",
        help="create a new PT-XXX row (auto-creates phase section if missing)",
    )
    ptt_parser.add_argument("--task", default="", help="task text for a new --create row")
    ptt_parser.add_argument(
        "--phase",
        default="",
        help="override phase for --create (otherwise inferred from PT-XXX id)",
    )
    ptt_parser.set_defaults(func=record_ptt)

    addhosts_parser = subparsers.add_parser(
        "add-hosts",
        help="append SCOPE-SCOPED IP->hostname entries to $ENG_DIR/state/hosts.allowed "
        "(engagement-local; never touches system /etc/hosts directly)",
    )
    addhosts_parser.add_argument("--eng-dir", required=True, help="engagement directory")
    addhosts_parser.add_argument(
        "--entry",
        required=True,
        nargs=2,
        action="append",
        metavar=("IP", "HOSTNAME"),
        help="repeatable 'IP HOSTNAME' pair; IP must be in-scope per scope.yaml and not excluded",
    )
    addhosts_parser.add_argument("--scope", default="", help="optional explicit scope.yaml path")
    addhosts_parser.set_defaults(func=add_hosts)

    cleanuphosts_parser = subparsers.add_parser(
        "cleanup-hosts", help="remove IPs from $ENG_DIR/state/hosts.allowed (engagement teardown)"
    )
    cleanuphosts_parser.add_argument("--eng-dir", required=True, help="engagement directory")
    cleanuphosts_parser.add_argument(
        "--ip",
        required=True,
        action="append",
        help="repeatable IP to remove from the engagement hosts allow-list",
    )
    cleanuphosts_parser.set_defaults(func=cleanup_hosts)

    skill_parser = subparsers.add_parser(
        "check-skill-loaded", help="mark SKILL.md as read for the current session/work-block"
    )
    skill_parser.add_argument("--eng-dir", required=True, help="engagement directory")
    skill_parser.add_argument(
        "--session-id", required=True, help="session or goal label, used in marker filename"
    )
    skill_parser.add_argument(
        "--skill-loaded-file",
        default="",
        help="write marker to explicit path; default: $ENG_DIR/state/.skill-loaded-<session-id>",
    )
    skill_parser.set_defaults(func=check_skill_loaded)

    history_parser = subparsers.add_parser(
        "record-history", help="append a timestamped entry to history.md"
    )
    history_parser.add_argument("--eng-dir", required=True, help="engagement directory")
    history_parser.add_argument("--command", required=True, help="shell command that was just run")
    history_parser.add_argument(
        "--exit-code", required=True, type=int, help="exit code of the command"
    )
    history_parser.add_argument("--phase", default="UNKNOWN", help="phase tag (default: UNKNOWN)")
    history_parser.add_argument(
        "--evidence", default="", help="evidence path under $ENG_DIR/evidence/"
    )
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
