"""Check-command sub-guards — pure validation functions.

This is the canonical command, freshness, and closeout policy implementation.
No subprocess calls — pure functions returning dataclasses.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from . import bootstrap, hypotheses, ptt, state
from . import history as history_mod
from .phases import Phase, normalize_phase, requires_hypothesis, suppresses_heartbeat
from .results import GuardResult
from .targets import (
    check_scope_targets,
    extract_target_candidates,
    normalise_target,
)

__all__ = [
    "CheckCommandArgs",
    "GuardResult",
    "CheckResult",
    "ScopeResult",
    "HypothesisResult",
    "SkillLoadResult",
    "check_command",
    "validate_scope",
    "check_scope_authorization",
    "check_skill_load",
    "check_hypothesis_freshness",
]


# ---------------------------------------------------------------------------
# Argument / Result dataclasses
# ---------------------------------------------------------------------------


@dataclass
class CheckCommandArgs:
    command: str
    phase: str
    eng_dir: str
    scope: str = ""
    target: str | None = None
    session_id: str | None = None
    skill_loaded_file: str | None = None


@dataclass
class CheckResult(GuardResult):
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
class HypothesisResult(CheckResult):
    hypothesis_count: int = 0


@dataclass
class SkillLoadResult(CheckResult):
    marker_path: str | None = None


# ---------------------------------------------------------------------------
# Scope validation
# ---------------------------------------------------------------------------


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

    assessment_hosts = data.get("assessment_hosts", {}) or {}
    if not isinstance(assessment_hosts, dict):
        result.add_error("scope.assessment_hosts must be a mapping when present")
    else:
        callback_hosts = assessment_hosts.get("callback_hosts", []) or []
        if not isinstance(callback_hosts, list) or any(
            not isinstance(item, str) or not item.strip() for item in callback_hosts
        ):
            result.add_error("scope.assessment_hosts.callback_hosts must be a list of hosts/IPs")

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
            f"phase {phase.value} is not permitted by scope.rules_of_engagement.allowed_actions; "
            f"add an allowed_actions entry containing one of: {', '.join(terms)}"
        )
    return result


# ---------------------------------------------------------------------------
# DANGEROUS-PATTERN ENFORCEMENT
# ---------------------------------------------------------------------------

_DESTRUCTIVE_PATTERNS: list[tuple[str, str]] = [
    (
        r"\brm\s+-[a-zA-Z]*r[a-zA-Z]*f[a-zA-Z]*\b",
        "destructive filesystem deletion (rm -rf) is blocked",
    ),
    (
        r"\brm\s+-[a-zA-Z]*f[a-zA-Z]*r[a-zA-Z]*\b",
        "destructive filesystem deletion (rm -fr) is blocked",
    ),
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


def check_local_artifact_paths(command: str) -> CheckResult:
    """Remind operators that locally-created scripts belong in the engagement."""
    result = CheckResult()
    if re.search(r"(?:>|\btee\s+)\s*/tmp/[^\s]+\.(?:py|pl|rb|sh)(?=\s|$)", command):
        result.add_info("local script path uses /tmp; save it under $ENG_DIR/exploits instead")
    return result


def check_skill_load(eng_dir: Path, session_id: str, mandatory: bool = True) -> SkillLoadResult:
    """Verify skill-load marker exists for the session."""
    result = SkillLoadResult()
    marker = eng_dir / "state" / f".skill-loaded-{session_id}"
    result.marker_path = str(marker)

    if not marker.exists():
        stale_markers = sorted((eng_dir / "state").glob(".skill-loaded-*"))
        stale_hint = ""
        if stale_markers:
            names = ", ".join(candidate.name for candidate in stale_markers[:3])
            stale_hint = (
                f"; found marker(s) for another session: {names}. "
                f"After loading the skill, create the canonical marker: {marker}"
            )
        if mandatory:
            result.add_error(f"skill-load gate not satisfied: marker missing{stale_hint}")
        else:
            result.add_warning(f"skill-load marker missing (non-mandatory mode){stale_hint}")
        return result

    content = marker.read_text(encoding="utf-8").strip()
    if "skill-loaded:" not in content:
        result.add_warning("skill-load marker exists but format is unexpected")

    result.add_info(f"skill-load marker verified: {marker}")
    return result


# ---------------------------------------------------------------------------
# Hypothesis freshness gate
# ---------------------------------------------------------------------------


def check_hypothesis_freshness(
    eng_dir: Path, phase: Phase, command: str, primary_target: str | None = None
) -> HypothesisResult:
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
    targets = {normalise_target(target) for target in extract_target_candidates(command)}
    if primary_target:
        targets.add(normalise_target(primary_target))
    relevant = []
    for hypothesis in hyps:
        if hypothesis.canonical_status() == "Rejected" or not hypothesis.target:
            continue
        try:
            hypothesis_phase = normalize_phase(hypothesis.phase)
        except ValueError:
            continue
        target = normalise_target(hypothesis.target)
        if hypothesis_phase in acceptable_phases and (not targets or target in targets):
            relevant.append(hypothesis)
    if not relevant:
        eligible = [
            f"H-{h.id}@{normalise_target(h.target)}"
            for h in hyps
            if h.canonical_status() != "Rejected" and h.target
        ]
        result.add_error(
            f"phase {phase.value} requires a non-rejected hypothesis matching the command target; "
            f"parsed targets: {', '.join(sorted(targets)) or 'none'}; "
            f"available hypotheses: {', '.join(eligible) or 'none'}"
        )
        return result

    if phase in {
        Phase.EXPLOITATION,
        Phase.POST_EXPLOITATION,
        Phase.PRIVESC,
        Phase.FLAGS,
    }:
        researched = [h for h in relevant if h.cve_research.strip() and h.exploit_research.strip()]
        if not researched:
            missing = []
            for h in relevant:
                fields = []
                if not h.cve_research.strip():
                    fields.append("CVE Research")
                if not h.exploit_research.strip():
                    fields.append("Exploit Research")
                missing.append(f"H-{h.id} missing {' and '.join(fields)}")
            result.add_error(
                "online research must be attempted and recorded before exploit execution; "
                + "; ".join(missing)
                + ". Record each query/source and outcome; 'no results', 'not applicable', "
                "or 'source unavailable' are valid outcomes when truthful."
            )
            return result
        relevant = researched

    # Check for stale hypotheses (no update in 48h)
    stale = 0
    now = datetime.now(UTC)
    for h in hyps:
        if not h.updated:
            continue
        ts = None
        raw = h.updated.strip()
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


# ---------------------------------------------------------------------------
# Main check-command orchestrator
# ---------------------------------------------------------------------------


def check_command(args: CheckCommandArgs) -> CheckResult:
    """Run all sub-guards for a target command."""
    eng_dir = state.resolve_eng_dir(args.eng_dir)
    scope_path = Path(args.scope) if args.scope else eng_dir / "scope" / "scope.yaml"
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

    # 2b. Scope target enforcement
    target_result = check_scope_targets(scope_path, args.command, args.target)
    result.errors.extend(target_result.errors)
    result.warnings.extend(target_result.warnings)

    # 2c. Destructive-pattern hard block
    destructive_result = check_destructive_patterns(args.command)
    result.errors.extend(destructive_result.errors)

    artifact_result = check_local_artifact_paths(args.command)
    result.infos.extend(artifact_result.infos)

    # 3. Skill-load gate (mandatory)
    session_id = state.resolve_session_id(eng_dir, args.session_id)
    if not session_id:
        result.add_error("session_id is required for the skill-load gate")
    if session_id:
        skill_result = check_skill_load(eng_dir, session_id, mandatory=True)
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
    pending = state.get_pending_sync(str(eng_dir)) or {}
    pending_commands = {str(item.get("command") or "") for item in pending.get("commands") or []}
    h_errors, h_warnings, h_infos = history_mod.check_history_staleness(
        eng_dir, args.command, allow_pending_repeat=args.command in pending_commands
    )
    result.errors.extend(h_errors)
    result.warnings.extend(h_warnings)
    result.infos.extend(h_infos)

    # 6. Hypothesis freshness
    hyp_result = check_hypothesis_freshness(eng_dir, phase, args.command, args.target)
    result.errors.extend(hyp_result.errors)
    result.warnings.extend(hyp_result.warnings)
    result.infos.extend(hyp_result.infos)

    # 7. Sync/heartbeat state
    sync_pending = state.get_pending_sync(str(eng_dir))
    if sync_pending:
        credit = state.sync_credit_remaining(str(eng_dir))
        last_command = (sync_pending.get("commands") or [{}])[-1].get(
            "command", sync_pending.get("command", "prior command")
        )
        if credit == 0:
            result.add_error(
                f"prior command's artifacts not synced: {last_command} "
                f"(phase: {sync_pending.get('phase')})"
            )
        else:
            result.add_info(
                f"bounded batch in progress after: {last_command} "
                f"(phase: {sync_pending.get('phase')}); {credit} credit(s) remain"
            )

    # 8. Sync-credit window exhausted
    credit = state.sync_credit_remaining(str(eng_dir))
    result.infos.append(f"sync credit remaining: {credit}/{state.DEFAULT_SYNC_CREDIT}")
    if credit == 0:
        result.add_error("sync-credit window exhausted — call violin_sync_done to reset")

    # 9. Heartbeat gate (set after every COMMAND_INTERVAL executed commands).
    # Execution owns the command count and creates the heartbeat lock after the
    # threshold command succeeds. Preflight only enforces that existing lock;
    # predicting the next count here would permanently block the threshold
    # command because blocked attempts do not advance the counter.
    if not suppresses_heartbeat(phase) and state.has_heartbeat_pending(str(eng_dir)):
        reason = state.get_heartbeat_reason(str(eng_dir))
        detail = f": {reason}" if reason else ""
        result.add_error(
            f"heartbeat pending{detail} — review engagement state, then run "
            "violin_heartbeat_done"
        )

    return result
