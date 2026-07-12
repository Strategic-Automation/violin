"""check-command and its sub-guards for the Violin guard package."""

from __future__ import annotations

import argparse
import re
import shlex
from pathlib import Path
from typing import Any

from hypothesis_guard import _parse_hypotheses

from guard.closeout import check_closeout
from guard.core import (
    DANGEROUS_PATTERNS,
    GUARD_APPROVED_EXFIL,
    LOCAL_TOOLS,
    METADATA_TARGETS,
    PHASES,
    TARGET_TOOLS,
    TIER3_PATTERNS,
    CheckResult,
    as_list,
    host_from_url,
    is_excluded_host,
    is_scoped_host,
    load_yaml,
    merge_result,
    normalize_host,
    resolve_eng_dir,
    validate_scope_data,
)
from guard.freshness import (
    check_findings_freshness,
    check_hypotheses_freshness,
    check_ptt_freshness,
    check_skill_load_gate,
)
from guard.record import _history_staleness_guard, _ptt_staleness_guard


def check_command(args: argparse.Namespace) -> int:
    """Public entrypoint: run the core gate and print the verdict."""
    result = _check_command_core(args)
    result.print()
    return result.exit_code()


def _check_command_core(args: argparse.Namespace) -> CheckResult:
    """Run the full target-touching safety gate WITHOUT printing.

    Returns the populated ``CheckResult`` so callers (e.g. the burst
    executor) can batch multiple commands and decide on a single aggregate
    verdict rather than printing per call.
    """
    scope_path = Path(args.scope)
    if not scope_path.exists():
        result = CheckResult()
        result.add_error(f"scope file not found: {scope_path}")
        # Check if the scope argument looks like an IP/host instead of a file path
        scope_arg = args.scope.strip()
        if re.match(r"^(\d{1,3}\.){3}\d{1,3}$", scope_arg) or re.match(
            r"^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$", scope_arg
        ):
            result.add_error(
                f"  → The value '{scope_arg}' looks like an IP address or hostname, not a file path."
            )
            result.add_error(
                "  → The --scope flag requires the PATH to your scope.yaml file (e.g. $ENG_DIR/scope/scope.yaml)"
            )
        result.add_error(
            "BOOTSTRAP REQUIRED: run playbooks/scoping.md §0 (Bootstrap) to create scope.yaml, PTT, hypothesis board, and command history before any target interaction"
        )
        result.add_info(
            'quickstart: ENG_DIR=engagements/<target>-$(date +%F); mkdir -p "$ENG_DIR"/{scope,evidence/{recon/{passive,tech,active},vuln-research,exploitation,reporting,retrospective},state}; cp skills/pentest/templates/{ptt.md,scope-template.yaml,hypothesis-board.md} "$ENG_DIR"/{state/ptt.md,scope/scope.yaml,hypotheses.md}'
        )
        result.print()
        return result
    scope = load_yaml(scope_path)
    result = CheckResult()
    phase = args.phase.upper().replace("-", "_")
    command = args.command.strip()
    lowered = command.lower()

    if phase not in PHASES:
        result.add_error(f"unknown phase: {args.phase}")

    scope_result = validate_scope_data(scope)
    if scope_result.errors:
        result.errors.extend(f"scope invalid: {error}" for error in scope_result.errors)

    for pattern, reason in DANGEROUS_PATTERNS:
        if re.search(pattern, lowered, flags=re.IGNORECASE):
            result.add_error(reason)

    # --- Privileged-escalation (sudo -S / piped password) guard (issue 1) ---
    # The old guard blocked ANY command containing `sudo -S` / a piped password,
    # even when the sudo ran *on the remote target inside an ssh command* — not
    # on the agent's own box. That forced elaborate workarounds (symlink + sudo
    # -n) for a perfectly legitimate `echo <pw> | sudo -S ...` as ben on the
    # target. We now distinguish "escalating the agent's own host" (BLOCK) from
    # "driving sudo on an authorised, scoped target via ssh/scp" (REVIEW, i.e.
    # allowed with explicit approval). A piped password to sudo on the agent's
    # own host is genuinely dangerous (credentials on the operator box); the
    # same idiom inside an ssh wrapper to a scoped target is routine PRIVESC.
    _check_sudo_escalation(command, lowered, scope, result)

    for pattern, reason in TIER3_PATTERNS:
        if re.search(pattern, lowered, flags=re.IGNORECASE):
            if "credential" in reason and has_allowed_carveout(
                scope, "credential", "brute", "password"
            ):
                result.add_warning(
                    f"{reason}; RoE carve-out found, require explicit per-command approval"
                )
            else:
                result.add_warning(reason)

    tokens = command_tokens(command)
    tool = Path(tokens[0]).name.lower() if tokens else ""
    hosts = extract_hosts(command)
    is_local = tool in LOCAL_TOOLS

    # Local interpreters and shell built-ins run on the operator's own box
    # (or local code). A host-like token in their arguments is just a path
    # (e.g. `engagements/10.10.10.10/...`, a script name, or a localhost
    # reference) — it is NOT a target-touching command, so it must not raise
    # the "unclassified tool" / scope-validation warnings, and must not
    # participate in the target-touching skill-load / pending-sync gates.
    if is_local:
        hosts = set()

    # --- Guard-Approved exfil channels (issue 4) ---
    # Reverse shells / file-transfer idioms are sanctioned loot movement paths,
    # but only when every command host is in the approved scope. If the same
    # command touches an off-scope/excluded host, let the scope gate below emit
    # the BLOCK without also printing a misleading Guard-Approved REVIEW.
    offscope_hosts = hosts and any(
        is_excluded_host(h, scope) or not is_scoped_host(h, scope) for h in hosts
    )
    if not offscope_hosts:
        for pattern, reason in GUARD_APPROVED_EXFIL:
            if re.search(pattern, lowered, flags=re.IGNORECASE):
                result.add_warning(reason)

    if tool and tool not in TARGET_TOOLS and tool not in LOCAL_TOOLS and hosts:
        result.add_warning(f"command uses unclassified tool '{tool}' against detected target(s)")

    if tool in TARGET_TOOLS and not hosts:
        result.add_warning("target-touching tool used but no target was detected; ask for review")

    for host in sorted(hosts):
        if host in METADATA_TARGETS and not has_allowed_carveout(scope, "metadata", "ssrf"):
            result.add_error(f"cloud metadata target is not scoped by default: {host}")
        elif is_excluded_host(host, scope):
            result.add_error(f"target is explicitly excluded: {host}")
        elif not is_scoped_host(host, scope):
            result.add_error(f"target is outside approved scope: {host}")

    if phase in {"SCOPING", "REPORTING", "RETROSPECTIVE"} and (hosts or tool in TARGET_TOOLS):
        result.add_error(f"target interaction is not allowed during {phase}")

    if phase in {"RECON", "VULN_RESEARCH"} and any(
        term in lowered for term in ("--os-pwn", "--risk=3", "reverse shell")
    ):
        result.add_error(f"exploit-style command is not allowed during {phase}")

    eng_dir = (args.eng_dir or "").strip()
    if eng_dir:
        eng_dir_path = Path(eng_dir)
        skill_loaded_file = getattr(args, "skill_loaded_file", "") or ""
        session_id = (getattr(args, "session_id", "") or "").strip()
        if session_id:
            canonical = eng_dir_path / "state" / f".skill-loaded-{session_id}"
            skill_loaded_file = str(canonical)

        # Skill-load gate is mandatory for any target-touching command when an
        # engagement dir is supplied (was discipline-only). Local tools
        # (cd, python3, ...) are never target-touching even if a host-like
        # token appears in their arguments, so they must not arm the gates.
        target_touching = bool((hosts or tool in TARGET_TOOLS) and not is_local) and phase in {
            "RECON",
            "VULN_RESEARCH",
            "EXPLOITATION",
            "POST_EXPLOITATION",
        }
        if target_touching:
            skill_result = check_skill_load_gate(skill_loaded_file, mandatory=True)
            merge_result(result, skill_result, prefix="skill guard")
        elif skill_loaded_file:
            # Non-target command with an explicit marker: verify but don't block.
            skill_result = check_skill_load_gate(skill_loaded_file, mandatory=False)
            merge_result(result, skill_result, prefix="skill guard")

        ptt_result = _ptt_staleness_guard(
            eng_dir_path / "state" / "ptt.md",
            eng_dir_path / "state" / "history.md",
        )
        merge_result(result, ptt_result, prefix="ptt guard")

        # Freshness guard: PTT "Last updated" + phase desync
        ptt_fresh = check_ptt_freshness(eng_dir_path / "state" / "ptt.md", phase)
        merge_result(result, ptt_fresh, prefix="ptt guard")

        history_result = _history_staleness_guard(eng_dir_path, lowered)
        merge_result(result, history_result, prefix="history guard")

        if (
            target_touching
            and phase in {"VULN_RESEARCH", "EXPLOITATION", "POST_EXPLOITATION"}
            and not result.errors
        ):
            hyp_result = _hypothesis_guard(eng_dir_path, hosts, phase)
            merge_result(result, hyp_result, prefix="hypothesis guard")

        # Freshness guard: hypotheses + findings drift
        hyp_fresh = check_hypotheses_freshness(eng_dir_path / "hypotheses.md", phase)
        merge_result(result, hyp_fresh, prefix="hypothesis guard")
        findings_fresh = check_findings_freshness(eng_dir_path, phase)
        merge_result(result, findings_fresh, prefix="findings guard")

        # Close-out gate: mandatory REPORTING / RETROSPECTIVE artifacts. These are
        # HARD errors (exit 1) so --yolo cannot auto-approve them (only warnings
        # are auto-approved). Permitted artifact-producing commands are exempt so
        # the agent can create the very file the gate requires (no deadlock).
        if phase in {"REPORTING", "RETROSPECTIVE"}:
            closeout = check_closeout(eng_dir_path, phase, command)
            merge_result(result, closeout, prefix="close-out gate")

    if not result.errors and not result.warnings:
        result.add_info("command is allowed by current lightweight guard")
    return result


def _hypothesis_guard(eng_dir: Path, hosts: set[str], phase: str) -> CheckResult:
    result = CheckResult()
    hypothesis_path = eng_dir / "hypotheses.md"
    if not hypothesis_path.exists() or not hypothesis_path.is_file():
        result.add_error(f"hypotheses.md missing: {hypothesis_path}")
        result.add_info(
            'bootstrap with: cp skills/pentest/templates/hypothesis-board.md "$ENG_DIR/hypotheses.md"'
        )
        return result
    try:
        hypotheses = _parse_hypotheses(hypothesis_path)
    except Exception as exc:
        result.add_error(f"hypotheses.md parse error: {exc}")
        return result
    active_hypotheses = [
        h for h in hypotheses if h.status in {"candidate", "researching", "verified"}
    ]
    if not active_hypotheses:
        result.add_error("no active hypotheses found; create one before continuing")
        result.add_info(
            'run: python scripts/hypothesis_guard.py record-hypothesis --eng-dir "$ENG_DIR" --service <service> --port <port> --status researching --rationale "<why>"'
        )
        return result
    for host in hosts:
        matched = [h for h in active_hypotheses if h.target and host.lower() in h.target.lower()]
        if not matched:
            result.add_warning(
                f"no hypothesis covers host {host}; add a hypothesis or verify scope before continuing"
            )
    if phase == "VULN_RESEARCH" and all(h.status != "verified" for h in active_hypotheses):
        result.add_warning(
            "active hypotheses exist but none are verified; research step required before exploitation"
        )
    return result


def command_tokens(command: str) -> list[str]:
    try:
        return shlex.split(command, posix=False)
    except ValueError:
        return command.split()


def extract_hosts(command: str) -> set[str]:
    hosts: set[str] = set()
    for url in re.findall(r"https?://[^\s'\"<>]+", command, flags=re.IGNORECASE):
        host = host_from_url(url)
        if host:
            hosts.add(host)
    hosts.update(
        normalize_host(item) for item in re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", command)
    )
    # Suffixes that denote a file/path segment rather than a hostname, so they
    # are not misclassified as out-of-scope target hosts (e.g. shell.php in a URL).
    _FILE_SUFFIXES = (
        ".txt",
        ".md",
        ".yaml",
        ".yml",
        ".json",
        ".py",
        ".sh",
        ".ps1",
        ".php",
        ".html",
        ".htm",
        ".asp",
        ".aspx",
        ".js",
        ".css",
        ".jsp",
        ".cgi",
        ".do",
        ".xml",
        ".csv",
    )
    for host in re.findall(r"\b[a-zA-Z0-9][a-zA-Z0-9.-]*\.[a-zA-Z]{2,}\b", command):
        normalized = normalize_host(host)
        if not normalized.endswith(_FILE_SUFFIXES):
            hosts.add(normalized)
    return hosts


def has_allowed_carveout(scope: dict[str, Any], *needles: str) -> bool:
    allowed = " ".join(
        str(item).lower()
        for item in as_list((scope.get("rules_of_engagement") or {}).get("allowed_actions"))
    )
    return any(needle in allowed for needle in needles)


# --- Privileged-escalation guard (issue 1) ----------------------------------
# The sudo escalation guard distinguishes *where* the escalation happens:
#
#   * Escalating the AGENT'S OWN HOST (the operator box) with a piped password
#     is BLOCKED — it would drop a target credential onto the operator's own
#     shell and is almost never legitimate.
#   * Driving sudo on an AUTHORISED, IN-SCOPE TARGET via an ssh/scp wrapper is
#     routine PRIVESC (e.g. `echo <benpw> | sudo -S ...` as ben on the box).
#     That is allowed but flagged REVIEW so the operator explicitly approves
#     the elevation against an approved target.
#
# Detection: we split the command on the ssh/scp connect boundary. Anything in
# an ssh/scp remote-command body (`ssh user@host '...'`, `scp ... host:'...'`,
# or `ssh -t host <<'EOF'`) is treated as TARGET-side, and sudo there is only
# blocked if the target itself is out of scope. Anything OUTSIDE an ssh wrapper
# that contains `sudo -S` / a piped password is treated as OWN-HOST escalation.
#
# Note: scope is optional (check-command may be called without --scope, e.g.
# for orchestration). When scope is unavailable we fall back to a conservative
# own-host BLOCK so we never implicitly allow operator-box escalation.

# Localhost tokens that, if a sudo escalation is seen next to them, clearly mark
# the agent's own host rather than a remote target.
_OWN_HOST_TOKENS = {"localhost", "127.0.0.1", "::1"}

# Patterns that denote a piped / askpass password feeding sudo.
_PIPED_PW_PATTERNS = [
    re.compile(r"(?:echo\s+.{0,64}?\s*\|\s*sudo\s+-S)"),  # echo <pw> | sudo -S ...
    re.compile(r"(?:sudo\s+-S\b)"),  # sudo -S (askpass / piped)
    re.compile(r"(?:\|\s*sudo\b[^|]*\b-S\b)"),  # ... | sudo ... -S ...
    re.compile(r"(?:sudo\b[^|]*\b-S\b[^|]*\|)"),  # sudo ... -S ... | ...
]

# scp connect pattern: user@host:path means the path is target-side.
_SCP_TARGET_RE = re.compile(r"[\w.-]+@[\w.-]+:")  # scp user@host:path (path is target-side)


def _sudo_in_text(text: str) -> bool:
    """True if ``text`` contains a password-fed sudo escalation idiom."""
    low = text.lower()
    return any(p.search(low) for p in _PIPED_PW_PATTERNS)


def _split_ssh_wrappers(command: str):
    """Split a command into (own_host_fragments, target_fragments).

    ``own_host_fragments`` are the pieces of the command that run on the
    operator box; ``target_fragments`` are the remote-command bodies that run
    on the remote target inside an ssh/scp invocation.
    """
    own_parts: list[str] = []
    target_parts: list[str] = []

    # Tokenise on ssh/scp so we can lift the trailing remote-command body.
    # We scan left-to-right; everything that is part of an ssh/scp connect +
    # remote command goes to target_parts, the rest to own_parts.
    pos = 0
    for m in re.finditer(r"(?P<conn>ssh\b[^\n|;&]*)", command, flags=re.IGNORECASE):
        # text before this ssh connect is own-host
        own_parts.append(command[pos : m.start()])
        seg = m.group("conn")
        # remote command is the last quoted/last token after the connection spec
        body = _ssh_remote_body(seg)
        if body is not None:
            target_parts.append(body)
        else:
            # No clear remote body (e.g. `ssh host` interactive) — treat the
            # whole connect spec as neutral; nothing escalates on own host here.
            pass
        pos = m.end()
    own_parts.append(command[pos:])

    # scp: user@host:path means the path is target-side. We strip the
    # target-side path and keep the rest as own-host.
    for _m in re.finditer(_SCP_TARGET_RE, command):
        target_parts.append(
            ""
        )  # scp path is target-side; escalation there is governed by scope, handled by host check
    return "\n".join(own_parts), "\n".join(target_parts)


def _ssh_remote_body(seg: str) -> str | None:
    """Extract the remote command body from an ssh connect fragment, if any."""
    # Last single/double-quoted string is the remote command.
    for q in ("'", '"'):
        # greedy match of the final quoted segment
        mm = re.search(rf"{q}([^{q}]*){q}\s*$", seg)
        if mm:
            return mm.group(1)
    # Otherwise the bare token after the host (e.g. ssh host id)
    mm = re.search(r"@[\w.-]+\s+(\S+)\s*$", seg) or re.search(r"\sssh\s+[\w.-]+\s+(\S+)\s*$", seg)
    if mm:
        return mm.group(1)
    return None


def _check_sudo_escalation(
    command: str, lowered: str, scope: dict | None, result: CheckResult
) -> None:
    """Apply the target-aware sudo escalation guard (issue 1)."""
    if not _sudo_in_text(command):
        return

    own_text, target_text = _split_ssh_wrappers(command)

    # Escalation on the operator's own host (excluding stuff that only appears
    # inside an ssh remote body) is BLOCKED.
    own_escalates = _sudo_in_text(own_text)
    if own_escalates:
        # If the only escalating text is clearly about localhost own-box, say so.
        if any(tok in lowered for tok in _OWN_HOST_TOKENS) and not target_text.strip():
            result.add_error(
                "PRIVESC BLOCKED: piped-password sudo escalation targets the "
                "AGENT'S OWN HOST (localhost). Escalating the operator box with a "
                "piped credential is not permitted — use the authorised run host "
                "or scoped target via ssh."
            )
        else:
            result.add_error(
                "PRIVESC BLOCKED: password-fed sudo escalation (`sudo -S` / piped "
                "password) detected OUTSIDE an ssh/scp wrapper — i.e. on the agent's "
                "own host. This is not permitted. To escalate on an authorised target, "
                "wrap it in ssh (e.g. `ssh ben@<target> 'echo <pw> | sudo -S <cmd>'`)."
            )
        return

    # Escalation appears only inside an ssh/scp remote body (target-side).
    if target_text.strip() and _sudo_in_text(target_text):
        if scope is None:
            # No scope available: stay conservative (block) — operator should
            # pass --scope so we can verify the target is authorised.
            result.add_error(
                "PRIVESC BLOCKED (no scope): sudo escalation is wrapped in ssh to a "
                "target but no --scope was supplied, so authorisation cannot be "
                "verified. Pass --scope <ENG_DIR>/scope/scope.yaml."
            )
            return
        # Verify every detected target host is in scope. If any target is
        # out of scope, escalate to BLOCK; otherwise allow with REVIEW.
        target_hosts = extract_hosts(target_text)
        oob = [
            h
            for h in target_hosts
            if not is_scoped_host(h, scope) and not is_excluded_host(h, scope)
        ]
        if oob:
            result.add_error(
                "PRIVESC BLOCKED: sudo escalation via ssh targets an OUT-OF-SCOPE "
                f"host: {', '.join(sorted(oob))}. Escalation is only permitted on "
                "authorised, in-scope targets."
            )
        else:
            result.add_warning(
                "PRIVESC REVIEW: password-fed sudo escalation wrapped in ssh to an "
                + (f"in-scope target {sorted(target_hosts)} " if target_hosts else "target ")
                + "— routine PRIVESC, but confirm the target is authorised and the "
                "escalation is intended before approving."
            )
        return

    # sudo -S present but the splitter couldn't attribute it (fallback).
    result.add_warning(
        "PRIVESC REVIEW: password-fed sudo (`sudo -S` / piped password) detected. "
        "Verify it escalates an authorised, in-scope TARGET via ssh, not the agent's "
        "own host. Own-host escalation is blocked."
    )


def add_hosts(args: argparse.Namespace) -> int:
    """Append scope-scoped hosts entries to an engagement-local hosts file.

    The guard refuses to touch the system ``/etc/hosts`` directly (privilege +
    portability hazard). Instead it maintains a per-engagement allow-list at
    ``$ENG_DIR/state/hosts.allowed`` that the skill can instruct the operator to
    source (e.g. ``sudo sh -c 'cat $ENG_DIR/state/hosts.allowed >> /etc/hosts'``).

    Every entry's IP must (a) be a valid IP literal, (b) match an in-scope
    target in scope.yaml, and (c) NOT be an excluded host. Anything else is
    BLOCKED (exit 1) with no file change.

    Arguments:
      --eng-dir      engagement directory
      --entry        repeatable ``IP HOSTNAME`` pair (e.g. ``10.10.10.5 web01``)
      --scope        optional explicit path to scope.yaml; defaults to
                     ``$ENG_DIR/scope/scope.yaml``

    Exit codes: 0 = appended, 1 = blocked (entry not in scope / invalid),
    2 = appended but with a non-fatal warning.
    """
    import ipaddress

    result = CheckResult()
    eng_dir = Path(resolve_eng_dir(args.eng_dir))
    if not eng_dir.exists():
        result.add_error(f"engagement directory not found: {eng_dir}")
        result.print()
        return 1

    scope_path = (
        Path(args.scope) if getattr(args, "scope", None) else (eng_dir / "scope" / "scope.yaml")
    )
    if not scope_path.exists():
        result.add_error(f"scope file not found: {scope_path}; cannot authorise host entries")
        result.print()
        return 1
    scope = load_yaml(scope_path)

    entries = getattr(args, "entry", None) or []
    if not entries:
        result.add_error("no --entry supplied; pass at least one 'IP HOSTNAME' pair")
        result.print()
        return 1

    approved: list[tuple[str, str]] = []
    seen: set[str] = set()
    for ip, hostname in entries:
        ip = ip.strip()
        hostname = hostname.strip()
        # 1) valid IP literal
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            result.add_error(f"'{ip}' is not a valid IP address; refusing entry for {hostname}")
            continue
        # 2) not an excluded host
        if is_excluded_host(ip, scope):
            result.add_error(f"'{ip}' ({hostname}) is an EXCLUDED host in scope.yaml")
            continue
        # 3) must be in scope
        if not is_scoped_host(ip, scope):
            result.add_error(
                f"'{ip}' ({hostname}) is NOT in scope per scope.yaml targets; "
                "refusing to add an out-of-scope host entry"
            )
            continue
        if ip in seen:
            result.add_warning(f"duplicate entry skipped: {ip} {hostname}")
            continue
        seen.add(ip)
        approved.append((ip, hostname))

    if result.errors:
        result.print()
        return 1

    hosts_file = eng_dir / "state" / "hosts.allowed"
    header = (
        "# Violin engagement-scoped hosts allow-list\n"
        "# Auto-managed by `violin_guard.py add-hosts`. Source into /etc/hosts only\n"
        f"# for engagement {eng_dir.name}. Do NOT hand-edit below this line.\n"
    )
    existing_lines = set()
    if hosts_file.exists():
        existing_lines = {ln.strip() for ln in hosts_file.read_text(encoding="utf-8").splitlines()}
    new_block: list[str] = []
    for ip, hostname in approved:
        line = f"{ip}\t{hostname}"
        if line in existing_lines:
            result.add_info(f"already present: {line}")
            continue
        new_block.append(line)
        result.add_info(f"approved: {line}")

    if new_block:
        content = hosts_file.read_text(encoding="utf-8") if hosts_file.exists() else ""
        if not content.endswith("\n") and content:
            content += "\n"
        if not hosts_file.exists():
            content = header
        content += "\n".join(new_block) + "\n"
        hosts_file.parent.mkdir(parents=True, exist_ok=True)
        hosts_file.write_text(content, encoding="utf-8")
        result.add_info(
            f"wrote {len(new_block)} new entr{'y' if len(new_block) == 1 else 'ies'} to {hosts_file}"
        )

    result.print()
    return 2 if result.warnings and not result.errors else 0


def cleanup_hosts(args: argparse.Namespace) -> int:
    """Remove IPs from an engagement-local hosts allow-list.

    Arguments:
      --eng-dir      engagement directory
      --ip          repeatable IP to remove from ``$ENG_DIR/state/hosts.allowed``

    Exit codes: 0 = list updated or no-op, 1 = engagement dir / hosts file missing.
    """
    result = CheckResult()
    eng_dir = Path(resolve_eng_dir(args.eng_dir))
    hosts_file = eng_dir / "state" / "hosts.allowed"
    if not hosts_file.exists():
        result.add_error(f"hosts allow-list not found: {hosts_file} (nothing to clean up)")
        result.print()
        return 1

    ips = {ip.strip() for ip in (getattr(args, "ip", None) or []) if ip.strip()}
    lines = hosts_file.read_text(encoding="utf-8").splitlines()
    kept: list[str] = []
    removed = 0
    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            kept.append(line)
            continue
        first = stripped.split()[0] if stripped.split() else ""
        if first in ips:
            removed += 1
            result.add_info(f"removed: {stripped}")
            continue
        kept.append(line)

    if removed:
        hosts_file.write_text("\n".join(kept).rstrip("\n") + "\n", encoding="utf-8")
        result.add_info(f"removed {removed} entr{'y' if removed == 1 else 'ies'} from {hosts_file}")
    else:
        result.add_info("no matching entries to remove")
    result.print()
    return 0
