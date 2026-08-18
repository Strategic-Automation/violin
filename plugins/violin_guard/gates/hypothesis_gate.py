"""Hypothesis board freshness, skill bindings, and command pattern sub-guards."""

from __future__ import annotations

import contextlib
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from ..core import hypotheses, state
from ..core.phases import Phase, normalize_phase, requires_hypothesis
from ..core.results import GuardResult
from ..core.skill_receipts import get_binding
from ..core.targets import normalize_target, resolve_command_targets
from .scope_gate import validate_scope

# Grace window for the record-as-you-go recency gate: evidence newer than the
# hypothesis board's last update by more than this many seconds blocks further
# target commands. 15 minutes is generous enough for burst timing/clock skew
# while still catching run-long bookkeeping deferral.
_RECORD_AS_YOU_GO_GRACE = 15 * 60

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

_HTTP_CLIENT_RE = re.compile(r"\b(?:curl|wget)\b", re.I)
_HTTP_URL_RE = re.compile(r"https?://\S+", re.I)
_HTTP_LONG_FLAG_RE = re.compile(
    r"-(?:include|verbose|head|dump-header|write-out|output|remote-name|output-document)\b",
    re.I,
)
_HTTP_OFFLINE_CAPTURE_RE = re.compile(
    r"-(?:o|O|output|remote-name|output-document)\b|\s>\s*[^\s|]+", re.I
)


@dataclass
class HypothesisResult(GuardResult):
    def print(self) -> None:
        for error in self.errors:
            print(f"BLOCK: {error}")
        for warning in self.warnings:
            print(f"REVIEW: {warning}")
        for info in self.infos:
            print(f"OK: {info}")


def check_destructive_patterns(command: str) -> HypothesisResult:
    """Return a BLOCK if the command matches a destructive pattern."""
    result = HypothesisResult()
    for pattern, reason in _DESTRUCTIVE_PATTERNS:
        if re.search(pattern, command):
            result.add_error(reason)
            break
    return result


def check_local_artifact_paths(command: str) -> HypothesisResult:
    """Remind operators that locally-created scripts belong in the engagement."""
    result = HypothesisResult()
    if re.search(r"(?:>|\btee\s+)\s*/tmp/[^\s]+\.(?:py|pl|rb|sh)(?=\s|$)", command):
        result.add_info("local script path uses /tmp; save it under $ENG_DIR/exploits instead")
    return result


def _has_short_flag(command: str, *flags: str) -> bool:
    """True if any single-dash short-flag cluster contains one of `flags`."""
    wanted = set(flags)
    return any(
        any(ch in wanted for ch in token) for token in re.findall(r"(?<!\S)-[A-Za-z]+", command)
    )


def check_http_proof_flags(command: str) -> HypothesisResult:
    """Review-level guard: HTTP probes must capture the response status/headers."""
    result = HypothesisResult()
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


def check_cross_engagement_paths(command: str, active_eng_dir: Path) -> HypothesisResult:
    """Block commands that reference a foreign engagement directory under engagements/."""
    result = HypothesisResult()
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


def check_skill_binding(
    eng_dir: Path, task_id: str, session_id: str, phase: Phase
) -> HypothesisResult:
    """Require a delivered, current-context receipt binding for target work."""
    result = HypothesisResult()
    binding = get_binding(eng_dir, task_id)
    if not binding:
        result.add_error(
            f"skill receipt binding missing for active task {task_id} — "
            "deliver the skill first (skill_view/skill view the required skill for "
            "this task), then re-run the command in the same session."
        )
        return result
    if binding.get("session_id") != session_id:
        result.add_error(
            "skill receipt binding belongs to a different session — re-view the "
            "skill in THIS session (skill_view) so the binding is re-issued here, "
            "or pass the original session_id."
        )
    current = state.read_json(eng_dir / "state" / "skills.json").get("context", {})
    if binding.get("context_generation") != current.get("generation"):
        result.add_error(
            "skill receipt binding is stale after context reset — re-view the "
            "required skill via skill_view to refresh the binding for the current "
            "context generation."
        )
    if not result.errors:
        result.add_info(f"skill receipt binding verified: {binding.get('skill')}")
    return result


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
        if not hypothesis.target:
            continue
        if hypothesis.canonical_status() == "Rejected" and norm_hyp_id is None:
            continue
        try:
            hypothesis_phase = normalize_phase(hypothesis.phase)
        except ValueError:
            if norm_hyp_id is not None and not str(hypothesis.phase or "").strip():
                hypothesis_phase = phase
            else:
                continue
        target = normalize_target(hypothesis.target)

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
            f"H-{hypothesis.id}@{normalize_target(hypothesis.target)}[phase:{hypothesis.phase}]"
            for hypothesis in hyps
            if hypothesis.canonical_status() != "Rejected" and hypothesis.target
        ]
        msg = (
            f"phase {phase.value} requires a non-rejected hypothesis matching the command target and acceptable phase "
            f"(acceptable phases for {phase.value}: {', '.join(phase_item.value for phase_item in sorted(acceptable_phases, key=lambda phase_candidate: phase_candidate.value))})"
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
        any_research = any(
            hypothesis.cve_research.strip() and hypothesis.exploit_research.strip()
            for hypothesis in relevant
        )
        if not any_research:
            example = relevant[0] if relevant else None
            result.add_warning(
                "hint: no CVE/Exploit research recorded yet — before writing a "
                "custom exploit, try a web search for prior work (CVE databases, "
                "ExploitDB, GitHub PoCs). Record the outcome via "
                "violin_record_hypothesis "
                f"id=H-{example.id if example else '00N'} "
                "cve_research='...' exploit_research='...' — 'no results', "
                "'not applicable', or 'source unavailable' are valid truthful "
                "outcomes. This is a hint, not a block: execution may proceed."
            )

    # Check for stale hypotheses (no update in 48h)
    stale = 0
    now = datetime.now(UTC)
    for hypothesis in hyps:
        if not hypothesis.updated:
            continue
        ts = None
        raw = hypothesis.updated.strip()
        candidate = raw.removesuffix(" UTC").removesuffix("Z").strip()
        with contextlib.suppress(ValueError):
            ts = datetime.fromisoformat(candidate)
        if ts is None:
            continue
        ts = ts.replace(tzinfo=UTC)
        if (now - ts).total_seconds() > 48 * 3600:
            stale += 1

    if stale:
        result.add_warning(f"hypothesis guard: {stale} hypothesis(es) not updated in 48h")

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
        for hypothesis in relevant:
            if not hypothesis.updated:
                continue
            raw = hypothesis.updated.strip()
            candidate = raw.removesuffix(" UTC").removesuffix("Z").strip()
            updated_ts = None
            with contextlib.suppress(ValueError):
                updated_ts = datetime.fromisoformat(candidate)
            if updated_ts is None:
                continue
            updated_ts = updated_ts.replace(tzinfo=UTC)
            board_epoch = updated_ts.timestamp()
            evidence_age_beyond_board = newest_evidence - board_epoch
            if evidence_age_beyond_board > _RECORD_AS_YOU_GO_GRACE:
                # Record-as-you-go is a hint, not a block: re-syncing the board after
                # every burst-loop probe drains the prompt budget and breaks the probe
                # rhythm. False-positive protection lives at finding formalization /
                # REPORTING close, not here — so warn at a natural checkpoint instead.
                result.add_warning(
                    "hint: hypothesis H-"
                    f"{hypothesis.id} predates the latest execution evidence — record the "
                    "batch result on the hypothesis board at a natural checkpoint "
                    "(violin_record_hypothesis: status, Test Response, Runtime Evidence, "
                    "Updated). This is a hint, not a block."
                )

    result.add_info("relevant active hypothesis found")
    return result


__all__ = [
    "HypothesisResult",
    "_RECORD_AS_YOU_GO_GRACE",
    "check_cross_engagement_paths",
    "check_destructive_patterns",
    "check_http_proof_flags",
    "check_hypothesis_freshness",
    "check_local_artifact_paths",
    "check_skill_binding",
]
