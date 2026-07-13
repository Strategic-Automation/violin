"""Check-command sub-guards — pure validation functions.

All logic ported from scripts/guard/{command,record,freshness,closeout}.py
No subprocess calls — pure functions returning dataclasses.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from . import bootstrap, hypotheses, ptt, state
from .phases import Phase, normalize_phase, requires_hypothesis

__all__ = [
    "CheckCommandArgs",
    "CheckResult",
    "ScopeResult",
    "PttResult",
    "HypothesisResult",
    "SkillLoadResult",
    "check_command",
    "validate_scope",
    "check_scope_authorization",
    "check_skill_load",
    "check_history_staleness",
    "check_hypothesis_freshness",
]


# --------------------------------------------------------------------------- #
# Argument / Result dataclasses
# --------------------------------------------------------------------------- #


@dataclass
class CheckCommandArgs:
    command: str
    phase: str
    eng_dir: str
    scope: str
    session_id: str | None = None
    skill_loaded_file: str | None = None


@dataclass
class CheckResult:
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    infos: list[str] = field(default_factory=list)

    def add_error(self, msg: str) -> None:
        self.errors.append(msg)

    def add_warning(self, msg: str) -> None:
        self.warnings.append(msg)

    def add_info(self, msg: str) -> None:
        self.infos.append(msg)

    def has_errors(self) -> bool:
        return len(self.errors) > 0

    def exit_code(self) -> int:
        if self.errors:
            return 1
        if self.warnings:
            return 2
        return 0

    def print(self) -> None:
        for e in self.errors:
            print(f"BLOCK: {e}")
        for w in self.warnings:
            print(f"REVIEW: {w}")
        for i in self.infos:
            print(f"OK: {i}")


@dataclass
class ScopeResult(CheckResult):
    scope_data: dict[str, Any] | None = None


@dataclass
class PttResult(CheckResult):
    active_task: str | None = None


@dataclass
class HypothesisResult(CheckResult):
    hypothesis_count: int = 0


@dataclass
class SkillLoadResult(CheckResult):
    marker_path: str | None = None


# --------------------------------------------------------------------------- #
# Scope validation
# --------------------------------------------------------------------------- #


def validate_scope(scope_path: Path) -> ScopeResult:
    """Validate scope.yaml structure and required fields."""
    result = ScopeResult()
    if not scope_path.exists():
        result.add_error(f"scope file not found: {scope_path}")
        return result

    try:
        import yaml

        data = yaml.safe_load(scope_path.read_text(encoding="utf-8"))
    except Exception as exc:
        result.add_error(f"scope.yaml parse error: {exc}")
        return result

    if not isinstance(data, dict):
        result.add_error("scope.yaml root must be a mapping")
        return result

    # Required sections
    for section in ("targets", "rules_of_engagement", "engagement"):
        if section not in data:
            result.add_error(f"scope.yaml missing required section: {section}")

    # A real scope must name the approving party and be explicitly confirmed.
    parties = data.get("authorized_parties")
    if not isinstance(parties, list) or not any(str(item).strip() for item in parties):
        result.add_error("scope.authorized_parties must be a non-empty list")
    authorisation = data.get("authorisation")
    if not isinstance(authorisation, dict) or authorisation.get("confirmed") is not True:
        result.add_error("scope.authorisation.confirmed must be true before target execution")

    # targets.ip_addresses
    targets = data.get("targets", {})
    if "ip_addresses" not in targets:
        result.add_error("scope.targets.ip_addresses is required")
    elif not isinstance(targets["ip_addresses"], list) or not targets["ip_addresses"]:
        result.add_error("scope.targets.ip_addresses must be a non-empty list")

    # rules_of_engagement
    roe = data.get("rules_of_engagement", {})
    allowed_actions = roe.get("allowed_actions") if isinstance(roe, dict) else None
    if not isinstance(allowed_actions, list) or not any(
        str(item).strip() for item in allowed_actions
    ):
        result.add_error("scope.rules_of_engagement.allowed_actions must be a non-empty list")

    # engagement.date
    engagement = data.get("engagement", {})
    if "date" not in engagement:
        result.add_warning("scope.engagement.date missing (will be set on init)")

    result.scope_data = data
    return result


_PHASE_ACTION_TERMS = {
    Phase.SCOPING: ("scope",),
    Phase.RECON: ("recon", "discovery", "banner", "version", "scan", "enumerat"),
    Phase.VULN_RESEARCH: ("vuln", "research", "cve", "exploitdb"),
    Phase.EXPLOITATION: ("exploit", "validation", "poc"),
    Phase.POST_EXPLOITATION: ("post-exploit", "post exploitation", "exploit", "validation"),
    Phase.PRIVESC: ("privilege", "privesc", "exploit", "validation"),
    Phase.FLAGS: ("flag", "capture"),
    Phase.REPORTING: ("report",),
    Phase.RETROSPECTIVE: ("retrospective",),
}


def check_scope_authorization(scope: dict[str, Any] | None, phase: Phase) -> CheckResult:
    """Ensure the approved rules of engagement allow the requested phase."""
    result = CheckResult()
    if not isinstance(scope, dict):
        return result
    roe = scope.get("rules_of_engagement") or {}
    allowed = [str(item).lower() for item in roe.get("allowed_actions", []) or []]
    forbidden = [str(item).lower() for item in roe.get("forbidden_actions", []) or []]
    terms = _PHASE_ACTION_TERMS[phase]
    if any(any(term in action for term in terms) for action in forbidden):
        result.add_error(
            f"phase {phase.value} conflicts with scope.rules_of_engagement.forbidden_actions"
        )
    if not any(any(term in action for term in terms) for action in allowed):
        result.add_error(
            f"phase {phase.value} is not permitted by scope.rules_of_engagement.allowed_actions"
        )
    return result


# --------------------------------------------------------------------------- #
# DANGEROUS-PATTERN ENFORCEMENT (audit P0: destructive commands were never
# blocked). These patterns are hard BLOCKs — yolo cannot bypass them.
# --------------------------------------------------------------------------- #

_DESTRUCTIVE_PATTERNS: list[tuple[str, str]] = [
    (
        r"\brm\s+-[a-zA-Z]*r[a-zA-Z]*f[a-zA-Z]*\b",
        "destructive filesystem deletion (rm -rf) is blocked",
    ),
    (
        r"\brm\s+-[a-zA-Z]*f[a-zA-Z]*r[a-zA-Z]*\b",
        "destructive filesystem deletion (rm -fr) is blocked",
    ),
    (r"\brm\s+-rf\b", "recursive force delete (rm -rf) is blocked"),
    (r"\brm\s+-r\b", "recursive delete (rm -r) is blocked"),
    (r"\bmkfs\.[a-z]+\b", "filesystem format (mkfs) is blocked"),
    (r"\bdd\b[^\n]*\bof=/dev/", "raw device overwrite (dd of=/dev/...) is blocked"),
    (r"\bwipefs\b", "filesystem wipe (wipefs) is blocked"),
    (r"\bshred\b[^\n]*\b/dev/", "device shred is blocked"),
    (r":\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:", "fork bomb is blocked"),
    (r">\s*/dev/sd[a-z]", "overwriting a block device is blocked"),
    (r"\bchmod\s+-R\s+0", "recursive permission wipe (chmod -R 0...) is blocked"),
    (r"\bchown\s+-R\b", "recursive ownership change (chown -R) is blocked"),
    (
        r"\b(?:curl|wget)\b[^\n|]*\|\s*(?:sudo\s+)?(?:ba)?sh\b",
        "piping a download into a shell is blocked",
    ),
]


def check_destructive_patterns(command: str) -> CheckResult:
    """Return a BLOCK if the command matches a destructive pattern."""
    result = CheckResult()
    for pattern, reason in _DESTRUCTIVE_PATTERNS:
        if re.search(pattern, command):
            result.add_error(reason)
            break
    return result


# --------------------------------------------------------------------------- #
# SCOPE TARGET ENFORCEMENT (audit P0: command targets were never compared with
# the engagement's allowed hosts). IPv4/CIDR literals must appear in scope;
# unknown hostnames force a REVIEW rather than a silent pass.
# --------------------------------------------------------------------------- #

_IPV4_CIDR = re.compile(r"(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?")
_HOST_PORT = re.compile(r"\b([A-Za-z0-9](?:[A-Za-z0-9-]*\.)*[A-Za-z0-9-]+):\d{1,5}\b")
_FQDN = re.compile(r"\b([A-Za-z0-9](?:[A-Za-z0-9-]*\.)+[A-Za-z]{2,})\b")


def _extract_target_candidates(command: str) -> list[str]:
    """Ordered, de-duplicated host/IP candidates from a command line."""
    cands: list[str] = []
    for m in re.finditer(r"https?://([^\s'\"<>]+)", command):
        host = m.group(1).split("/")[0].split("@")[-1]
        if ":" in host:
            host = host.split(":", 1)[0]
        if host:
            cands.append(host.lower())
    for m in _IPV4_CIDR.finditer(command):
        cands.append(m.group(0).lower())
    # Validate colon-containing tokens with ipaddress instead of treating the
    # leading hextet of an IPv6 address as a host:port pair.
    for token in re.findall(r"(?<![\w:])\[?[0-9A-Fa-f:]{2,}\]?(?:/\d{1,3})?", command):
        candidate = token.strip("[]").lower()
        try:
            ipaddress.ip_network(candidate, strict=False)
        except ValueError:
            continue
        cands.append(candidate)
    for m in _HOST_PORT.finditer(command):
        cands.append(m.group(1).lower())
    for m in _FQDN.finditer(command):
        cands.append(m.group(1).lower())
    seen: set[str] = set()
    out: list[str] = []
    for c in cands:
        if c and c not in seen:
            seen.add(c)
            out.append(c)
    return out


def _values(value: Any):
    if isinstance(value, dict):
        for nested in value.values():
            yield from _values(nested)
    elif isinstance(value, list):
        for nested in value:
            yield from _values(nested)
    elif value is not None:
        yield str(value)


def _normalise_scope_host(value: str) -> str:
    match = re.match(r"https?://([^\s/]+)", value, flags=re.IGNORECASE)
    host = match.group(1) if match else value
    if host.startswith("[") and "]" in host:
        return host[1 : host.index("]")].lower()
    return host.rsplit(":", 1)[0].lower() if host.count(":") == 1 else host.lower()


def _scope_allowed_hosts(scope: dict) -> set[str]:
    allowed: set[str] = set()
    targets = scope.get("targets", {}) or {}
    for key in ("ip_addresses", "in_scope_urls", "urls", "domains", "hostnames", "roles"):
        for value in _values(targets.get(key, [])):
            allowed.add(_normalise_scope_host(value))
    return allowed


def _scope_excluded_hosts(scope: dict) -> set[str]:
    excluded: set[str] = set()
    for item in _values(scope.get("exclusions", {})):
        excluded.add(_normalise_scope_host(item))
    return excluded


def _scope_networks(scope: dict, section: str) -> list[ipaddress._BaseNetwork]:
    values = []
    targets = scope.get(section, {}) or {}
    for key in ("ip_addresses", "cidrs"):
        values.extend(_values(targets.get(key, [])))
    networks = []
    for value in values:
        try:
            networks.append(ipaddress.ip_network(value, strict=False))
        except ValueError:
            continue
    return networks


def _matches_network(candidate: str, networks: list[ipaddress._BaseNetwork]) -> bool:
    try:
        network = ipaddress.ip_network(candidate, strict=False)
    except ValueError:
        return False
    return any(
        network.version == allowed.version and network.subnet_of(allowed) for allowed in networks
    )


def check_scope_targets(scope_path: Path, command: str) -> CheckResult:
    """Block commands whose IP/CIDR target is outside the engagement scope."""
    result = CheckResult()
    if not scope_path.exists():
        return result
    try:
        import yaml

        data = yaml.safe_load(scope_path.read_text(encoding="utf-8")) or {}
    except Exception:
        return result
    if not isinstance(data, dict):
        return result

    allowed = _scope_allowed_hosts(data)
    excluded = _scope_excluded_hosts(data)
    allowed_networks = _scope_networks(data, "targets")
    excluded_networks = _scope_networks(data, "exclusions")
    for cand in _extract_target_candidates(command):
        if cand in excluded or _matches_network(cand, excluded_networks):
            result.add_error(f"excluded target {cand} must not be touched")
            continue
        if cand in allowed:
            continue
        if _matches_network(cand, allowed_networks):
            continue
        try:
            ipaddress.ip_network(cand, strict=False)
            is_ip = True
        except ValueError:
            is_ip = False
        if is_ip:
            result.add_error(f"out-of-scope target {cand} (not present in scope.yaml)")
        else:
            result.add_warning(f"host {cand} is not present in scope.yaml; verify authorization")
    return result


def check_skill_load(eng_dir: Path, session_id: str, mandatory: bool = True) -> SkillLoadResult:
    """Verify skill-load marker exists for the session."""
    result = SkillLoadResult()
    marker = eng_dir / "state" / f".skill-loaded-{session_id}"
    result.marker_path = str(marker)

    if not marker.exists():
        if mandatory:
            result.add_error("skill-load gate not satisfied: marker missing")
        else:
            result.add_warning("skill-load marker missing (non-mandatory mode)")
        return result

    content = marker.read_text(encoding="utf-8").strip()
    if "skill-loaded:" not in content:
        result.add_warning("skill-load marker exists but format is unexpected")

    result.add_info(f"skill-load marker verified: {marker}")
    return result


# --------------------------------------------------------------------------- #
# History staleness (duplicate detection)
# --------------------------------------------------------------------------- #


def check_history_staleness(eng_dir: Path, command: str) -> CheckResult:
    """Check if the command would be an exact repeat of the last recorded command."""
    result = CheckResult()
    hist_path = eng_dir / "state" / "history.md"

    if not hist_path.exists():
        result.add_info("history.md does not exist — will be recorded after command runs")
        return result

    content = hist_path.read_text(encoding="utf-8")
    lines = [line.strip() for line in content.splitlines() if line.strip()]

    if not lines:
        result.add_info("history.md is empty — first command will be recorded")
        return result

    # Check for exact duplicate of last command
    last_line = lines[-1]
    if command in last_line:
        result.add_error(
            f"command appears to be an exact repeat of the last recorded command: {last_line}"
        )

    return result


# --------------------------------------------------------------------------- #
# Hypothesis freshness gate
# --------------------------------------------------------------------------- #


def check_hypothesis_freshness(eng_dir: Path, phase: Phase, command: str) -> HypothesisResult:
    """Ensure hypotheses exist and are fresh for phases that require them."""
    result = HypothesisResult()

    if not requires_hypothesis(phase):
        return result

    hyp_path = eng_dir / "hypotheses.md"
    hyps = hypotheses.parse_hypotheses(hyp_path)
    result.hypothesis_count = len(hyps)

    if not hyps:
        result.add_error(f"phase {phase.value} requires at least one hypothesis in hypotheses.md")
        return result

    acceptable_phases = {
        Phase.VULN_RESEARCH: {Phase.VULN_RESEARCH},
        Phase.EXPLOITATION: {Phase.VULN_RESEARCH, Phase.EXPLOITATION},
        Phase.POST_EXPLOITATION: {Phase.EXPLOITATION, Phase.POST_EXPLOITATION},
        Phase.PRIVESC: {Phase.EXPLOITATION, Phase.POST_EXPLOITATION, Phase.PRIVESC},
        Phase.FLAGS: {Phase.PRIVESC, Phase.FLAGS},
    }.get(phase, {phase})
    targets = set(_extract_target_candidates(command))
    relevant = []
    for hypothesis in hyps:
        if hypothesis.canonical_status() == "Rejected" or not hypothesis.target:
            continue
        try:
            hypothesis_phase = normalize_phase(hypothesis.phase)
        except ValueError:
            continue
        target = _normalise_scope_host(hypothesis.target)
        if hypothesis_phase in acceptable_phases and (not targets or target in targets):
            relevant.append(hypothesis)
    if not relevant:
        result.add_error(
            f"phase {phase.value} requires a non-rejected hypothesis matching the command target"
        )
        return result

    # Check for stale hypotheses (no update in 48h)
    stale = 0
    now = datetime.now(UTC)
    for h in hyps:
        if not h.updated:
            continue
        ts = None
        raw = h.updated.strip()
        # Normalise common suffixes: " UTC", "Z"
        candidate = raw.removesuffix(" UTC").removesuffix("Z").strip()
        for fmt in ("%Y-%m-%d %H:%M", "%Y-%m-%dT%H:%M", "%Y-%m-%d %H:%M:%S"):
            try:
                ts = datetime.strptime(candidate, fmt)
                break
            except ValueError:
                continue
        if ts is None:
            continue
        ts = ts.replace(tzinfo=UTC)
        if (now - ts).total_seconds() > 48 * 3600:
            stale += 1

    if stale:
        result.add_warning(f"hypothesis guard: {stale} hypothesis(es) not updated in 48h")

    return result


# --------------------------------------------------------------------------- #
# Main check-command orchestrator
# --------------------------------------------------------------------------- #


def check_command(args: CheckCommandArgs) -> CheckResult:
    """Run all sub-guards for a target command."""
    eng_dir = Path(args.eng_dir)
    scope_path = Path(args.scope)
    phase = normalize_phase(args.phase)

    result = CheckResult()

    # 1. Bootstrap completeness
    bootstrap_result = bootstrap.check_bootstrap(str(eng_dir), auto_repair=False)
    result.errors.extend(bootstrap_result.errors)
    result.warnings.extend(bootstrap_result.warnings)
    result.infos.extend(bootstrap_result.infos)

    # 2. Scope validation
    scope_result = validate_scope(scope_path)
    result.errors.extend(scope_result.errors)
    result.warnings.extend(scope_result.warnings)

    authorisation_result = check_scope_authorization(scope_result.scope_data, phase)
    result.errors.extend(authorisation_result.errors)

    # 2b. Scope target enforcement (audit P0). Extract command targets and
    #     block anything that lands on an out-of-scope IP/CIDR.
    target_result = check_scope_targets(scope_path, args.command)
    result.errors.extend(target_result.errors)
    result.warnings.extend(target_result.warnings)

    # 2c. Destructive-pattern hard block (audit P0).
    destructive_result = check_destructive_patterns(args.command)
    result.errors.extend(destructive_result.errors)

    # 3. Skill-load gate (mandatory). Without a session_id the command cannot
    #    be authorized at all.
    if not args.session_id:
        result.add_error("session_id is required for the skill-load gate")
    if args.session_id:
        skill_result = check_skill_load(eng_dir, args.session_id, mandatory=True)
        result.errors.extend(skill_result.errors)
        result.warnings.extend(skill_result.warnings)
        result.infos.extend(skill_result.infos)

    # 4. PTT active task
    ptt_path = eng_dir / "state" / "ptt.md"
    ptt_validation = ptt.validate_ptt(ptt.parse_ptt(ptt_path))
    result.errors.extend(ptt_validation.errors)
    result.warnings.extend(ptt_validation.warnings)
    if ptt_validation.active_task:
        result.infos.append(f"active PTT task: {ptt_validation.active_task}")
        active_task = ptt.find_active_task(ptt_validation.tasks)
        if active_task and not ptt.task_matches_phase(active_task, phase):
            result.add_error(
                f"active PTT task {active_task.id} belongs to {active_task.phase or 'no phase'}; "
                f"requested phase is {phase.value}"
            )

    # 5. History staleness (duplicate detection)
    hist_result = check_history_staleness(eng_dir, args.command)
    result.errors.extend(hist_result.errors)
    result.warnings.extend(hist_result.warnings)
    result.infos.extend(hist_result.infos)

    # 6. Hypothesis freshness
    hyp_result = check_hypothesis_freshness(eng_dir, phase, args.command)
    result.errors.extend(hyp_result.errors)
    result.warnings.extend(hyp_result.warnings)
    result.infos.extend(hyp_result.infos)

    # 7. Sync/heartbeat state
    if state.has_pending_sync(str(eng_dir)):
        pending = state.get_pending_sync(str(eng_dir))
        if pending:
            credit = state.sync_credit_remaining(str(eng_dir))
            last_command = (pending.get("commands") or [{}])[-1].get(
                "command", pending.get("command", "prior command")
            )
            if credit == 0:
                # Hard block only after sync-credit window exhausted
                result.add_error(
                    f"prior command's artifacts not synced: {last_command} "
                    f"(phase: {pending.get('phase')})"
                )
            else:
                # A bounded batch is intentionally allowed to consume its five
                # credits.  This must be informational, not a REVIEW: otherwise
                # handle_exec denies command two unless global YOLO mode is on.
                result.add_info(
                    f"bounded batch in progress after: {last_command} "
                    f"(phase: {pending.get('phase')}); {credit} credit(s) remain"
                )

    # 8. Sync-credit window exhausted
    credit = state.sync_credit_remaining(str(eng_dir))
    if credit == 0:
        result.add_error("sync-credit window exhausted — call violin_sync_done to reset")

    # 9. Heartbeat gate (every COMMAND_INTERVAL commands, except in exploit phases)
    if not state.suppresses_heartbeat(phase):
        cmd_count = state.read_counts(str(eng_dir)).get("commands", 0)
        next_count = cmd_count + 1
        if next_count % state.COMMAND_INTERVAL == 0:
            if not state.has_heartbeat_pending(str(eng_dir)):
                state.set_heartbeat_pending(
                    str(eng_dir),
                    f"Reached {next_count} executed target commands. Review engagement files for drift.",
                )
            result.add_error(
                f"heartbeat pending: reached {next_count} commands — run violin_heartbeat_done"
            )

    return result
