"""check-command and its sub-guards for the Violin guard package."""

from __future__ import annotations

import argparse
import re
import shlex
from pathlib import Path
from typing import Any

from guard.core import (
    PHASES,
    TARGET_TOOLS,
    DANGEROUS_PATTERNS,
    TIER3_PATTERNS,
    METADATA_TARGETS,
    as_list,
    is_scoped_host,
    is_excluded_host,
    load_yaml,
    normalize_host,
    host_from_url,
    validate_scope_data,
    CheckResult,
)
from guard.record import _ptt_staleness_guard, _history_staleness_guard
from guard.freshness import (
    check_skill_load_gate,
    check_ptt_freshness,
    check_hypotheses_freshness,
    check_findings_freshness,
)
from guard.closeout import check_closeout
from hypothesis_guard import _parse_hypotheses


def check_command(args: argparse.Namespace) -> int:
    scope_path = Path(args.scope)
    if not scope_path.exists():
        result = CheckResult()
        result.add_error(f"scope file not found: {scope_path}")
        # Check if the scope argument looks like an IP/host instead of a file path
        scope_arg = args.scope.strip()
        if re.match(r"^(\d{1,3}\.){3}\d{1,3}$", scope_arg) or re.match(r"^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$", scope_arg):
            result.add_error(f"  → The value '{scope_arg}' looks like an IP address or hostname, not a file path.")
            result.add_error("  → The --scope flag requires the PATH to your scope.yaml file (e.g. $ENG_DIR/scope/scope.yaml)")
        result.add_error("BOOTSTRAP REQUIRED: run playbooks/scoping.md §0 (Bootstrap) to create scope.yaml, PTT, hypothesis board, and command history before any target interaction")
        result.add_info("quickstart: ENG_DIR=engagements/<target>-$(date +%F); mkdir -p \"$ENG_DIR\"/{scope,evidence/{recon/{passive,tech,active},vuln-research,exploitation,reporting,retrospective},state}; cp skills/pentest/templates/{ptt.md,scope-template.yaml,hypothesis-board.md} \"$ENG_DIR\"/{state/ptt.md,scope/scope.yaml,hypotheses.md}")
        result.print()
        return 1
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

    for pattern, reason in TIER3_PATTERNS:
        if re.search(pattern, lowered, flags=re.IGNORECASE):
            if "credential" in reason and has_allowed_carveout(scope, "credential", "brute", "password"):
                result.add_warning(f"{reason}; RoE carve-out found, require explicit per-command approval")
            else:
                result.add_warning(reason)

    tokens = command_tokens(command)
    tool = Path(tokens[0]).name.lower() if tokens else ""
    hosts = extract_hosts(command)

    if tool and tool not in TARGET_TOOLS and hosts:
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

    if phase in {"RECON", "VULN_RESEARCH"} and any(term in lowered for term in ("--os-pwn", "--risk=3", "reverse shell")):
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
        # engagement dir is supplied (was discipline-only).
        target_touching = bool(hosts or tool in TARGET_TOOLS) and phase in {
            "RECON", "VULN_RESEARCH", "EXPLOITATION",
        }
        if target_touching:
            skill_result = check_skill_load_gate(skill_loaded_file, mandatory=True)
            if skill_result.errors or skill_result.warnings:
                result.errors.extend(f"skill guard: {message}" for message in skill_result.errors)
                result.warnings.extend(f"skill guard: {message}" for message in skill_result.warnings)
                for message in skill_result.infos:
                    if message not in result.infos:
                        result.infos.append(message)
        elif skill_loaded_file:
            # Non-target command with an explicit marker: verify but don't block.
            skill_result = check_skill_load_gate(skill_loaded_file, mandatory=False)
            if skill_result.warnings:
                result.warnings.extend(f"skill guard: {message}" for message in skill_result.warnings)
                for message in skill_result.infos:
                    if message not in result.infos:
                        result.infos.append(message)

        ptt_result = _ptt_staleness_guard(eng_dir_path / "state" / "ptt.md")
        if ptt_result.errors or ptt_result.warnings:
            result.errors.extend(f"ptt guard: {message}" for message in ptt_result.errors)
            result.warnings.extend(f"ptt guard: {message}" for message in ptt_result.warnings)
            for message in ptt_result.infos:
                if message not in result.infos:
                    result.infos.append(message)

        # Freshness guard: PTT "Last updated" + phase desync
        ptt_fresh = check_ptt_freshness(eng_dir_path / "state" / "ptt.md", phase)
        if ptt_fresh.warnings:
            result.warnings.extend(f"ptt guard: {message}" for message in ptt_fresh.warnings)
            for message in ptt_fresh.infos:
                if message not in result.infos:
                    result.infos.append(message)

        history_result = _history_staleness_guard(eng_dir_path, lowered)
        if history_result.errors or history_result.warnings:
            result.errors.extend(f"history guard: {message}" for message in history_result.errors)
            result.warnings.extend(f"history guard: {message}" for message in history_result.warnings)
            for message in history_result.infos:
                if message not in result.infos:
                    result.infos.append(message)

        if target_touching and not result.errors:
            hyp_result = _hypothesis_guard(eng_dir_path, hosts, phase)
            if hyp_result.errors or hyp_result.warnings:
                result.errors.extend(f"hypothesis guard: {message}" for message in hyp_result.errors)
                result.warnings.extend(f"hypothesis guard: {message}" for message in hyp_result.warnings)
                for message in hyp_result.infos:
                    if message not in result.infos:
                        result.infos.append(message)

        # Freshness guard: hypotheses + findings drift
        hyp_fresh = check_hypotheses_freshness(eng_dir_path / "hypotheses.md", phase)
        if hyp_fresh.errors or hyp_fresh.warnings:
            result.errors.extend(f"hypothesis guard: {message}" for message in hyp_fresh.errors)
            result.warnings.extend(f"hypothesis guard: {message}" for message in hyp_fresh.warnings)
        findings_fresh = check_findings_freshness(eng_dir_path, phase)
        if findings_fresh.warnings:
            result.warnings.extend(f"findings guard: {message}" for message in findings_fresh.warnings)

        # Close-out gate: mandatory REPORTING / RETROSPECTIVE artifacts. These are
        # HARD errors (exit 1) so --yolo cannot auto-approve them (only warnings
        # are auto-approved). Permitted artifact-producing commands are exempt so
        # the agent can create the very file the gate requires (no deadlock).
        if phase in {"REPORTING", "RETROSPECTIVE"}:
            closeout = check_closeout(eng_dir_path, phase, command)
            if closeout.errors:
                result.errors.extend(f"close-out gate: {message}" for message in closeout.errors)
            for message in closeout.infos:
                if message not in result.infos:
                    result.infos.append(message)

    if not result.errors and not result.warnings:
        result.add_info("command is allowed by current lightweight guard")
    result.print()
    return result.exit_code()


def _hypothesis_guard(eng_dir: Path, hosts: set[str], phase: str) -> CheckResult:
    result = CheckResult()
    hypothesis_path = eng_dir / "hypotheses.md"
    if not hypothesis_path.exists() or not hypothesis_path.is_file():
        result.add_error(f"hypotheses.md missing: {hypothesis_path}")
        result.add_info("bootstrap with: cp skills/pentest/templates/hypothesis-board.md \"$ENG_DIR/hypotheses.md\"")
        return result
    try:
        hypotheses = _parse_hypotheses(hypothesis_path)
    except Exception as exc:
        result.add_error(f"hypotheses.md parse error: {exc}")
        return result
    active_hypotheses = [h for h in hypotheses if h.status in {"candidate", "researching", "verified"}]
    if not active_hypotheses:
        result.add_error("no active hypotheses found; create one before continuing")
        result.add_info("run: python scripts/hypothesis_guard.py record-hypothesis --eng-dir \"$ENG_DIR\" --service <service> --port <port> --status researching --rationale \"<why>\"")
        return result
    for host in hosts:
        matched = [h for h in active_hypotheses if h.target and host.lower() in h.target.lower()]
        if not matched:
            result.add_warning(f"no hypothesis covers host {host}; add a hypothesis or verify scope before continuing")
    if phase in {"RECON", "VULN_RESEARCH"} and all(h.status != "verified" for h in active_hypotheses):
        result.add_warning("active hypotheses exist but none are verified; research step required before exploitation")
    return result


def _skill_loaded_guard(skill_loaded_file: str) -> CheckResult:
    result = CheckResult()
    marker = Path(skill_loaded_file)
    if not marker.exists() or not marker.is_file():
        result.add_error("skill load gate: SKILL.md has not been marked as loaded for this session")
        result.add_info("load with: read_file path=skills/pentest/SKILL.md")
        result.add_info("then run: python scripts/violin_guard.py check-skill-loaded --eng-dir \"$ENG_DIR\" --session-id \"<session label>\"")
        return result
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
    hosts.update(normalize_host(item) for item in re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", command))
    # Suffixes that denote a file/path segment rather than a hostname, so they
    # are not misclassified as out-of-scope target hosts (e.g. shell.php in a URL).
    _FILE_SUFFIXES = (
        ".txt", ".md", ".yaml", ".yml", ".json", ".py", ".sh", ".ps1",
        ".php", ".html", ".htm", ".asp", ".aspx", ".js", ".css",
        ".jsp", ".cgi", ".do", ".xml", ".csv",
    )
    for host in re.findall(r"\b[a-zA-Z0-9][a-zA-Z0-9.-]*\.[a-zA-Z]{2,}\b", command):
        normalized = normalize_host(host)
        if not normalized.endswith(_FILE_SUFFIXES):
            hosts.add(normalized)
    return hosts


def has_allowed_carveout(scope: dict[str, Any], *needles: str) -> bool:
    allowed = " ".join(str(item).lower() for item in as_list((scope.get("rules_of_engagement") or {}).get("allowed_actions")))
    return any(needle in allowed for needle in needles)
