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
from .skill_receipts import get_binding
from .targets import (
    check_scope_targets,
    is_research_host,
    normalise_target,
    resolve_command_targets,
)

__all__ = [
    "CheckCommandArgs",
    "GuardResult",
    "CheckResult",
    "ScopeResult",
    "HypothesisResult",
    "check_command",
    "validate_scope",
    "check_scope_authorization",
    "check_skill_binding",
    "check_hypothesis_freshness",
]


# ---------------------------------------------------------------------------
# Argument / Result dataclasses
# ---------------------------------------------------------------------------

# Grace window for the record-as-you-go recency gate: evidence newer than the
# hypothesis board's last update by more than this many seconds blocks further
# target commands. 15 minutes is generous enough for burst timing/clock skew
# while still catching run-long bookkeeping deferral.
_RECORD_AS_YOU_GO_GRACE = 15 * 60


@dataclass
class CheckCommandArgs:
    command: str
    phase: str
    eng_dir: str
    scope: str = ""
    target: str | None = None
    session_id: str | None = None
    account_sync: bool = True
    hypothesis_id: str | None = None


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
    pass


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

    # A scope may identify targets by IP, CIDR, domain, hostname, URL, or role.
    # Requiring an IP address made otherwise valid web/domain engagements fail
    # before the workflow could reach authorization and execution.
    targets = data.get("targets", {})
    if not isinstance(targets, dict):
        result.add_error("scope.targets must be a mapping")
    else:
        target_fields = ("ip_addresses", "cidrs", "domains", "hostnames", "urls", "in_scope_urls")
        has_list_target = any(
            isinstance(targets.get(field), list)
            and any(str(item).strip() for item in targets.get(field, []))
            for field in target_fields
        )
        roles = targets.get("roles")
        has_role_target = isinstance(roles, dict) and any(
            (isinstance(value, list) and any(str(item).strip() for item in value))
            or (isinstance(value, str) and value.strip())
            for value in roles.values()
        )
        if not has_list_target and not has_role_target:
            result.add_error(
                "scope.targets must contain at least one IP, CIDR, domain, hostname, URL, or role"
            )

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


_PHASE_ACTIONS = {
    Phase.SCOPING: frozenset({"scope", "scoping"}),
    Phase.RECON: frozenset(
        {
            "recon",
            "discovery",
            "host port discovery",
            "host-port-discovery",
            "banner grabbing",
            "banner-grabbing",
            "version detection",
            "version-detection",
            "scanning",
            "enumeration",
        }
    ),
    Phase.VULN_RESEARCH: frozenset(
        {
            "vulnerability research",
            "vulnerability-research",
            "vuln-research",
            "research",
            "cve-research",
            "exploitdb",
        }
    ),
    Phase.EXPLOITATION: frozenset(
        {
            "exploitation",
            "exploit validation",
            "exploit-validation",
            "poc",
            "poc validation",
            "poc-validation",
        }
    ),
    Phase.POST_EXPLOITATION: frozenset({"post-exploitation", "post exploitation"}),
    Phase.PRIVESC: frozenset({"privilege escalation", "privilege-escalation", "privesc"}),
    Phase.FLAGS: frozenset({"flags", "flag capture", "flag-capture"}),
    Phase.REPORTING: frozenset({"report", "reporting"}),
    Phase.RETROSPECTIVE: frozenset({"retrospective"}),
}


def _normalise_action(value: object) -> str:
    return " ".join(
        str(value).strip().lower().replace("_", " ").replace("/", " ").replace("-", " ").split()
    )


def _action_key(value: object) -> str:
    """Normalize one exact action alias while allowing trailing qualifiers."""
    raw = str(value).strip()
    while re.search(r"\s*\([^()]*\)\s*$", raw):
        raw = re.sub(r"\s*\([^()]*\)\s*$", "", raw).strip()
    return _normalise_action(raw)


_ACTION_PHASES = {
    _action_key(alias): phase for phase, aliases in _PHASE_ACTIONS.items() for alias in aliases
}


def accepted_action_aliases(phase: Phase) -> list[str]:
    """Return the exact documented spellings accepted for one phase."""
    return sorted(_PHASE_ACTIONS[phase])


def map_scope_actions(items: Any) -> tuple[dict[str, str], list[str]]:
    """Map exact scope actions to phases and retain unrecognized entries."""
    recognized: dict[str, str] = {}
    unknown: list[str] = []
    for item in items if isinstance(items, list) else []:
        mapped = _ACTION_PHASES.get(_action_key(item))
        if mapped is None:
            unknown.append(str(item))
        else:
            recognized[str(item)] = mapped.value
    return recognized, unknown


def _is_action_permitted(allowed_items: Any, phase_actions: frozenset[str]) -> bool:
    accepted = {_action_key(action) for action in phase_actions}
    return any(_action_key(item) in accepted for item in allowed_items)


def check_scope_authorization(scope: dict[str, Any] | None, phase: Phase) -> CheckResult:
    """Ensure the approved rules of engagement allow the requested phase."""
    result = CheckResult()
    if not isinstance(scope, dict):
        return result
    roe = scope.get("rules_of_engagement") or {}
    raw_allowed = roe.get("allowed_actions", []) or []
    forbidden = {_action_key(item) for item in roe.get("forbidden_actions", []) or []}
    actions = _PHASE_ACTIONS[phase]
    accepted = {_action_key(action) for action in actions}
    if forbidden & accepted:
        result.add_error(
            f"phase {phase.value} conflicts with scope.rules_of_engagement.forbidden_actions"
        )
    if not _is_action_permitted(raw_allowed, actions):
        allowed_options = accepted_action_aliases(phase)
        formatted_options = ", ".join(f"'{act}'" for act in allowed_options)
        current_str = ", ".join(f"'{item}'" for item in raw_allowed) or "none"
        mapped, unknown = map_scope_actions(raw_allowed)
        mapped_str = ", ".join(f"'{key}' -> {value}" for key, value in mapped.items()) or "none"
        unknown_str = ", ".join(f"'{item}'" for item in unknown) or "none"
        result.add_error(
            f"phase {phase.value} is not permitted by scope.rules_of_engagement.allowed_actions "
            f"(current allowed_actions: [{current_str}]). "
            f"Recognized mappings: [{mapped_str}]. Unrecognized entries: [{unknown_str}]. "
            f"Select and add one of the following valid action strings for {phase.value} to "
            f"rules_of_engagement.allowed_actions in scope/scope.yaml (one of: [{formatted_options}])"
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


_HTTP_CLIENT_RE = re.compile(r"\b(?:curl|wget)\b", re.I)
_HTTP_URL_RE = re.compile(r"https?://\S+", re.I)
_HTTP_LONG_FLAG_RE = re.compile(
    r"-(?:include|verbose|head|dump-header|write-out|output|remote-name|output-document)\b",
    re.I,
)
# Offline captures (`-o file`, `-O`, `-e/--output`, `> file`) are not
# interactive HTTP evidence; status probes via `-w` are separately exempted.
_HTTP_OFFLINE_CAPTURE_RE = re.compile(
    r"-(?:o|O|output|remote-name|output-document)\b|\s>\s*[^\s|]+", re.I
)


def _has_short_flag(command: str, *flags: str) -> bool:
    """True if any single-dash short-flag cluster contains one of `flags`.

    Handles combined clusters (`-si`, `-sv`, `-Dk`) and separate tokens
    (`-s -i`). Case-sensitive on purpose: `-D` (dump-header) counts while
    `-d` (POST data) does not. Guarded to letters-only tokens to avoid
    matching data payloads or stray dashes.
    """
    wanted = set(flags)
    return any(
        any(ch in wanted for ch in token) for token in re.findall(r"(?<!\S)-[A-Za-z]+", command)
    )


def check_http_proof_flags(command: str) -> CheckResult:
    """Review-level guard: HTTP probes must capture the response status/headers.

    SKILL.md §4 mandates `-i` or `-sv` when testing HTTP endpoints so evidence
    files carry empirical status lines. Receipts from plain `curl -s` (no `-i`)
    make `has_decisive_proof` fail at validation time and burn real
    confirmations. Exempted: status probes (`-w %{http_code}`), HEAD (`-I`),
    header dumps (`-D`), and offline captures (`-o`/`-O`/`> file`) that are
    not interactive HTTP evidence.
    """
    result = CheckResult()
    if not _HTTP_CLIENT_RE.search(command) or not _HTTP_URL_RE.search(command):
        return result
    if _HTTP_LONG_FLAG_RE.search(command) or _HTTP_OFFLINE_CAPTURE_RE.search(command):
        return result
    if _has_short_flag(command, "i", "v", "I", "D", "w", "o", "O"):
        return result
    result.add_warning(
        "HTTP probe without status/headers capture: add `-i` (or `-sv`) to curl "
        "so the evidence file records the response status line — plain `-s` "
        "produces no HTTP/1.1 line and fails decisive-proof scoring"
    )
    return result


def check_cross_engagement_paths(command: str, active_eng_dir: Path) -> CheckResult:
    """Block commands that reference a foreign engagement directory under engagements/.

    The active engagement may be referenced (the agent legitimately reads its
    own evidence); any OTHER engagement directory is off-limits — whether from
    a previous run or a different client — to keep engagements isolated.
    """
    result = CheckResult()
    pattern = r"(?i)(?:[/\\]|^)engagements[/\\]([a-zA-Z0-9_-]+)\b"
    active_name = active_eng_dir.name
    for match in re.finditer(pattern, command):
        ref_name = match.group(1)
        if ref_name != active_name:
            result.add_error(
                f"cross-engagement path access blocked: command references foreign engagement directory '{ref_name}' "
                f"while active engagement is '{active_name}'"
            )
            break
    return result


def check_skill_binding(eng_dir: Path, task_id: str, session_id: str, phase: Phase) -> CheckResult:
    """Require a delivered, current-context receipt binding for target work."""
    result = CheckResult()
    binding = get_binding(eng_dir, task_id)
    if not binding:
        result.add_error(f"skill receipt binding missing for active task {task_id}")
        return result
    if binding.get("session_id") != session_id:
        result.add_error("skill receipt binding belongs to a different session")
    current = state.read_json(eng_dir / "state" / "skills.json").get("context", {})
    if binding.get("context_generation") != current.get("generation"):
        result.add_error("skill receipt binding is stale after context reset")
    if not result.errors:
        result.add_info(f"skill receipt binding verified: {binding.get('skill')}")
    return result


# ---------------------------------------------------------------------------
# Hypothesis freshness gate
# ---------------------------------------------------------------------------


def check_hypothesis_freshness(
    eng_dir: Path,
    phase: Phase,
    command: str,
    primary_target: str | None = None,
    hypothesis_id: str | None = None,
    *,
    match_command_target: bool = True,
) -> HypothesisResult:
    """Ensure hypotheses exist and are fresh for phases that require them."""
    result = HypothesisResult()

    if not requires_hypothesis(phase):
        return result

    hyp_path = eng_dir / "hypotheses.md"
    hyps = hypotheses.parse_hypotheses(hyp_path)

    if not hyps:
        result.add_error(
            f"phase {phase.value} requires at least one hypothesis in hypotheses.md. "
            f"Use violin_record_hypothesis (e.g. id='H-001' title='...' target='...' "
            f"phase='{phase.value}' status='Candidate') before executing target commands."
        )
        return result

    acceptable_phases = {
        Phase.VULN_RESEARCH: {Phase.RECON, Phase.VULN_RESEARCH},
        Phase.EXPLOITATION: {Phase.RECON, Phase.VULN_RESEARCH, Phase.EXPLOITATION},
        Phase.POST_EXPLOITATION: {
            Phase.RECON,
            Phase.VULN_RESEARCH,
            Phase.EXPLOITATION,
            Phase.POST_EXPLOITATION,
        },
        Phase.PRIVESC: {
            Phase.RECON,
            Phase.VULN_RESEARCH,
            Phase.EXPLOITATION,
            Phase.POST_EXPLOITATION,
            Phase.PRIVESC,
        },
        Phase.FLAGS: {
            Phase.RECON,
            Phase.VULN_RESEARCH,
            Phase.EXPLOITATION,
            Phase.POST_EXPLOITATION,
            Phase.PRIVESC,
            Phase.FLAGS,
        },
    }.get(phase, {phase})
    scope_path = eng_dir / "scope" / "scope.yaml"
    scope_data = validate_scope(scope_path).scope_data if scope_path.exists() else None
    targets = resolve_command_targets(command, primary_target=primary_target, scope_data=scope_data)

    norm_hyp_id = (
        hypothesis_id.strip().upper().removeprefix("H-").lstrip("0") or "0"
        if hypothesis_id
        else None
    )

    relevant = []
    for hypothesis in hyps:
        # A Rejected hypothesis is normally ineligible as a command target.
        # Exception: when the agent explicitly links a hypothesis_id, allow a
        # Rejected hypothesis to match so it can run the cheapest discriminating
        # test that the phase-close gate requires before a rejection may stand.
        # Without this, rejecting-then-testing deadlocks: the close gate refuses
        # to accept an untested rejection while this filter refuses to run the
        # test against a Rejected hypothesis.
        if not hypothesis.target:
            continue
        if hypothesis.canonical_status() == "Rejected" and norm_hyp_id is None:
            continue
        # A hypothesis with no phase recorded (empty/unknown) defaults to the
        # current execution phase when the agent explicitly links it — an
        # unphased hypothesis created during VULN_RESEARCH must still be
        # testable in VULN_RESEARCH, otherwise it can never be dispositioned
        # and the phase-close gate deadlocks. Non-linked unphased hypotheses
        # remain ineligible.
        try:
            hypothesis_phase = normalize_phase(hypothesis.phase)
        except ValueError:
            if norm_hyp_id is not None and not str(hypothesis.phase or "").strip():
                hypothesis_phase = phase
            else:
                continue
        target = normalise_target(hypothesis.target)

        if norm_hyp_id is not None:
            h_id = hypothesis.id.strip().upper().removeprefix("H-").lstrip("0") or "0"
            if h_id != norm_hyp_id:
                continue

        if hypothesis_phase in acceptable_phases and (
            not match_command_target or not targets or target in targets
        ):
            relevant.append(hypothesis)
    if not relevant:
        eligible = [
            f"H-{h.id}@{normalise_target(h.target)}[phase:{h.phase}]"
            for h in hyps
            if h.canonical_status() != "Rejected" and h.target
        ]
        msg = (
            f"phase {phase.value} requires a non-rejected hypothesis matching the command target and acceptable phase "
            f"(acceptable phases for {phase.value}: {', '.join(p.value for p in sorted(acceptable_phases, key=lambda x: x.value))})"
        )
        if norm_hyp_id:
            msg += f" (linked H-{norm_hyp_id.zfill(3)})"
        msg += (
            f"; parsed target(s): {', '.join(sorted(targets)) or 'none'}; "
            f"available hypotheses: {', '.join(eligible) or 'none'}. "
            f"To update a hypothesis's phase or status, use violin_record_hypothesis or edit hypotheses.md."
        )
        result.add_error(msg)
        return result

    if phase in {
        Phase.EXPLOITATION,
        Phase.POST_EXPLOITATION,
        Phase.PRIVESC,
        Phase.FLAGS,
    }:
        # Online research is required before exploit execution: the engagement
        # brief may have no exploit path, so the first action for any real
        # exploit is to look for prior work. When the command names a specific
        # hypothesis, only that hypothesis must carry research rows; otherwise
        # every candidate hypothesis must. 'no results' / 'not applicable' /
        # 'source unavailable' are valid truthful outcomes.
        if norm_hyp_id is not None:
            research_targets = [
                h
                for h in relevant
                if (h.id.strip().upper().removeprefix("H-").lstrip("0") or "0") == norm_hyp_id
            ]
        else:
            research_targets = relevant
        researched = [
            h for h in research_targets if h.cve_research.strip() and h.exploit_research.strip()
        ]
        if len(researched) < len(research_targets):
            missing = []
            for h in research_targets:
                if h.cve_research.strip() and h.exploit_research.strip():
                    continue
                fields = []
                if not h.cve_research.strip():
                    fields.append("CVE Research")
                if not h.exploit_research.strip():
                    fields.append("Exploit Research")
                missing.append(f"H-{h.id} missing {' and '.join(fields)}")
            result.add_error(
                "online research must be attempted and recorded before exploit execution; "
                + "; ".join(missing)
                + ". Record each query/source/outcome via violin_record_hypothesis "
                "id=H-00N cve_research='...' exploit_research='...' — 'no results', "
                "'not applicable', or 'source unavailable' are valid outcomes when "
                "truthful."
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

    # Recency gate — record-as-you-go enforcement. If the newest execution
    # evidence is NEWER than the hypothesis board's last update, the agent is
    # deferring bookkeeping and will reconstruct results from conversation
    # memory later (the false-positive factory). Block further commands until
    # the result is recorded on the board via violin_record_hypothesis.
    # Bursts preflight every command before any executes, so this never
    # false-fires mid-burst; a grace window absorbs same-burst timing skew.
    exec_dir = eng_dir / "evidence" / "executions"
    newest_evidence = 0.0
    if exec_dir.is_dir():
        for path in exec_dir.iterdir():
            if path.suffix == ".json" and not path.name.endswith((".lock", ".tmp")):
                try:
                    newest_evidence = max(newest_evidence, path.stat().st_mtime)
                except OSError:
                    continue
    if newest_evidence:
        for h in relevant:
            if not h.updated:
                continue
            raw = h.updated.strip()
            candidate = raw.removesuffix(" UTC").removesuffix("Z").strip()
            updated_ts = None
            for fmt in ("%Y-%m-%d %H:%M", "%Y-%m-%dT%H:%M", "%Y-%m-%d %H:%M:%S"):
                try:
                    updated_ts = datetime.strptime(candidate, fmt)
                    break
                except ValueError:
                    continue
            if updated_ts is None:
                continue
            updated_ts = updated_ts.replace(tzinfo=UTC)
            # evidence mtime is naive epoch — treat as UTC for comparison
            if newest_evidence > updated_ts.timestamp() + _RECORD_AS_YOU_GO_GRACE:
                result.add_error(
                    f"hypothesis H-{h.id} has not been updated since the latest execution "
                    "evidence — record the batch result on the hypothesis board NOW via "
                    "violin_record_hypothesis (status, Test Response, Runtime Evidence, "
                    "Updated) before running further commands. Deferred bookkeeping forces "
                    "memory-based reconstruction and is how false positives are born."
                )
                break  # one clear blocker per check is enough

    return result


# ---------------------------------------------------------------------------
# Main check-command orchestrator
# ---------------------------------------------------------------------------


def check_command(args: CheckCommandArgs) -> CheckResult:
    """Run all sub-guards for a target command."""
    eng_dir = state.resolve_eng_dir(args.eng_dir)
    canonical_scope_path = (eng_dir / "scope" / "scope.yaml").resolve()
    requested_scope_path = (
        Path(args.scope).expanduser().resolve() if args.scope else canonical_scope_path
    )
    scope_path = canonical_scope_path
    phase = normalize_phase(args.phase)

    result = CheckResult()

    if requested_scope_path != canonical_scope_path:
        result.add_error(
            "runtime execution must use the engagement's canonical scope.yaml; "
            "validate alternate scope files separately with validate-scope"
        )

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
    research_primary = bool(
        args.target
        and isinstance(scope_result.scope_data, dict)
        and is_research_host(scope_result.scope_data, args.target)
    )
    target_result = check_scope_targets(
        scope_path,
        args.command,
        args.target,
        allow_research_primary=research_primary,
    )
    result.errors.extend(target_result.errors)
    result.warnings.extend(target_result.warnings)
    if research_primary:
        if phase is not Phase.VULN_RESEARCH:
            result.add_error(
                "research_hosts may be explicit execution targets only during VULN_RESEARCH"
            )
        else:
            result.add_info(
                f"authorized research endpoint: {normalise_target(args.target or '')} "
                "(not an assessment target)"
            )

    # 2c. Destructive-pattern hard block
    destructive_result = check_destructive_patterns(args.command)
    result.errors.extend(destructive_result.errors)

    # 2c2. HTTP proof flags (review): `-i`/`-sv` so receipts are decisive
    proof_result = check_http_proof_flags(args.command)
    result.warnings.extend(proof_result.warnings)
    result.infos.extend(proof_result.infos)

    artifact_result = check_local_artifact_paths(args.command)
    result.infos.extend(artifact_result.infos)

    # 3. Session identity gate
    session_id = state.resolve_session_id(eng_dir, args.session_id)
    if not session_id:
        result.add_error("session_id is required for the skill receipt gate")

    # 4. PTT active task
    ptt_path = eng_dir / "state" / "ptt.md"
    ptt_validation = ptt.validate_ptt(ptt.parse_ptt(ptt_path))
    result.errors.extend(ptt_validation.errors)
    result.warnings.extend(ptt_validation.warnings)
    active_task_hyp_id = None
    if ptt_validation.active_task:
        result.infos.append(f"active PTT task: {ptt_validation.active_task}")
        active_task = ptt.find_active_task(ptt_validation.tasks)
        if active_task and not ptt.task_matches_phase(active_task, phase):
            task_phase_display = active_task.phase or "RECON (unspecified '## Phase:' header)"
            result.add_error(
                f"active PTT task {active_task.id} phase is '{task_phase_display}' (heading-derived from '## Phase:' section in state/ptt.md); "
                f"requested phase is '{phase.value}'. Next action: call violin_status, then update state/ptt.md so task {active_task.id} sits under a '## Phase: {phase.value}' header "
                f"or pass phase='{phase.value}' when updating task status via violin_record_ptt."
            )
        if active_task and active_task.note:
            hyp_match = re.search(r"\bH-\d+\b", active_task.note, re.IGNORECASE)
            if hyp_match:
                active_task_hyp_id = hyp_match.group(0).upper()
        if active_task and session_id:
            binding_result = check_skill_binding(eng_dir, active_task.id, session_id, phase)
            result.errors.extend(binding_result.errors)
            result.warnings.extend(binding_result.warnings)
            result.infos.extend(binding_result.infos)

    semantic_lock = state.semantic_lock(eng_dir)
    if semantic_lock:
        result.add_error(
            "semantic anti-stuck lock: five evidence-poor reviews require a recorded research "
            "attempt plus a meaningful next_technique pivot before target execution"
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
    hyp_result = check_hypothesis_freshness(
        eng_dir,
        phase,
        args.command,
        args.target,
        hypothesis_id=args.hypothesis_id or active_task_hyp_id,
        match_command_target=not research_primary,
    )
    result.errors.extend(hyp_result.errors)
    result.warnings.extend(hyp_result.warnings)
    result.infos.extend(hyp_result.infos)

    # 7-8. Target execution accounting. Strictly local analysis remains
    # auditable, but it must not consume or be blocked by target sync credit.
    if args.account_sync:
        sync_pending = state.get_pending_sync(str(eng_dir))
        if sync_pending:
            credit = state.sync_credit_remaining(str(eng_dir), phase.value)
            last_command = (sync_pending.get("commands") or [{}])[-1].get(
                "command", sync_pending.get("command", "prior command")
            )
            if credit == 0:
                result.add_error(
                    f"prior command's artifacts not synced: {last_command} "
                    f"(phase: {sync_pending.get('phase')}). Next: review the batch evidence and call "
                    "violin_review_batch with the active PTT task and a truthful note"
                )
            else:
                result.add_info(
                    f"bounded batch in progress after: {last_command} "
                    f"(phase: {sync_pending.get('phase')}); {credit} credit(s) remain"
                )

        credit = state.sync_credit_remaining(str(eng_dir), phase.value)
        credit_limit = int(
            (sync_pending or {}).get("credit_limit") or state.sync_credit_limit(phase.value)
        )
        result.infos.append(f"sync credit remaining: {credit}/{credit_limit}")
        if credit == 0:
            result.add_error(
                "sync-credit window exhausted; review the saved batch evidence, then call "
                "violin_review_batch (refreshes sync credit)"
            )
    else:
        result.add_info("local analysis is recorded without target sync-credit accounting")

    # 9. Heartbeat gate (set after every COMMAND_INTERVAL executed commands).
    # Execution owns the command count and creates the heartbeat lock after the
    # threshold command succeeds. Preflight only enforces that existing lock;
    # predicting the next count here would permanently block the threshold
    # command because blocked attempts do not advance the counter.
    if (
        args.account_sync
        and not suppresses_heartbeat(phase)
        and state.has_heartbeat_pending(str(eng_dir))
    ):
        reason = state.get_heartbeat_reason(str(eng_dir))
        detail = f": {reason}" if reason else ""
        result.add_error(
            f"heartbeat pending{detail} — review engagement state, then run violin_heartbeat_done. "
            "If this run has executed many commands (large context), compact/summarize your "
            "conversation now to stay under the provider prompt-token limit."
        )

    return result
