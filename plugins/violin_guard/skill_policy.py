"""Declarative, fail-closed policy for Violin skill selection.

This module intentionally has no Hermes or state dependency.  It defines the
approved vocabulary and routing rules that later delivery/enforcement layers
consume, so policy changes can be reviewed without changing execution.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

from .phases import Phase, normalize_phase

__all__ = [
    "CATALOG",
    "RouteDecision",
    "SkillSpec",
    "catalog_snapshot",
    "resolve_skill_route",
    "validate_catalog",
    "validate_skill_selection",
]


@dataclass(frozen=True)
class SkillSpec:
    """One reviewed skill dependency and its provenance requirements."""

    name: str
    source: str
    local_name: str
    trust: str
    install_hint: str
    approved_bundle_digest: str | None
    digest_required_on_install: bool = False


@dataclass(frozen=True)
class RouteDecision:
    """Deterministic skill choice plus every policy-permitted alternative."""

    phase: str
    vulnerability_class: str
    candidate_source: str
    selected: str | None
    allowed: tuple[str, ...]
    mismatch_reasons: tuple[str, ...]


# A remote dependency is deliberately not assigned an invented content hash.
# Its bundle digest is captured only by the approved Hermes install/audit flow;
# ``digest_required_on_install`` means a later delivery layer must reject an
# unpinned installation.  Bundled skills receive their content digest when the
# distributable snapshot is generated.
CATALOG: tuple[SkillSpec, ...] = (
    SkillSpec(
        "pentest", "bundled:skills/pentest", "pentest", "bundled", "included with Violin", None
    ),
    SkillSpec(
        "web-attacks",
        "bundled:skills/web-attacks",
        "web-attacks",
        "bundled",
        "included with Violin",
        None,
    ),
    SkillSpec(
        "access-control",
        "bundled:skills/access-control",
        "access-control",
        "bundled",
        "included with Violin",
        None,
    ),
    SkillSpec(
        "domain-intel",
        "official/research/domain-intel",
        "domain-intel",
        "official",
        "hermes skills install official/research/domain-intel",
        None,
        True,
    ),
    SkillSpec(
        "osint-investigation",
        "official/research/osint-investigation",
        "osint-investigation",
        "official",
        "hermes skills install official/research/osint-investigation",
        None,
        True,
    ),
    SkillSpec(
        "sherlock",
        "official/security/sherlock",
        "sherlock",
        "official",
        "hermes skills install official/security/sherlock",
        None,
        True,
    ),
    SkillSpec(
        "oss-forensics",
        "official/security/oss-forensics",
        "oss-forensics",
        "official",
        "hermes skills install official/security/oss-forensics",
        None,
        True,
    ),
    SkillSpec(
        "audit-context-building",
        "trailofbits/skills/plugins/audit-context-building/skills/audit-context-building",
        "audit-context-building",
        "reviewed-third-party",
        "hermes skills install trailofbits/skills/plugins/audit-context-building/skills/audit-context-building",
        None,
        True,
    ),
    SkillSpec(
        "semgrep",
        "trailofbits/skills/plugins/static-analysis/skills/semgrep",
        "semgrep",
        "reviewed-third-party",
        "hermes skills install trailofbits/skills/plugins/static-analysis/skills/semgrep",
        None,
        True,
    ),
    SkillSpec(
        "codeql",
        "trailofbits/skills/plugins/static-analysis/skills/codeql",
        "codeql",
        "reviewed-third-party",
        "hermes skills install trailofbits/skills/plugins/static-analysis/skills/codeql",
        None,
        True,
    ),
    SkillSpec(
        "sarif-parsing",
        "trailofbits/skills/plugins/static-analysis/skills/sarif-parsing",
        "sarif-parsing",
        "reviewed-third-party",
        "hermes skills install trailofbits/skills/plugins/static-analysis/skills/sarif-parsing",
        None,
        True,
    ),
    SkillSpec(
        "fp-check",
        "trailofbits/skills/plugins/fp-check/skills/fp-check",
        "fp-check",
        "reviewed-third-party",
        "hermes skills install trailofbits/skills/plugins/fp-check/skills/fp-check",
        None,
        True,
    ),
)

_CATALOG_BY_NAME = {spec.name: spec for spec in CATALOG}
_EXCLUDED_SOURCES = frozenset(
    {
        "official/security/godmode",
        "official/security/web-pentest",
        "yayalingo/kali-pentest-agent/skills",
        "yaklang/hack-skills",
    }
)

_VULNERABILITY_ROUTES = {
    "access-control": "access-control",
    "auth-bypass": "access-control",
    "authentication": "access-control",
    "authorization": "access-control",
    "idor": "access-control",
    "jwt": "access-control",
    "command-injection": "web-attacks",
    "path-traversal": "web-attacks",
    "sqli": "web-attacks",
    "sql-injection": "web-attacks",
    "ssrf": "web-attacks",
    "xss": "web-attacks",
    "source-analysis": "audit-context-building",
    "static-analysis": "semgrep",
    "sarif": "sarif-parsing",
    "false-positive": "fp-check",
}
_SOURCE_ROUTES = {
    "domain": "domain-intel",
    "osint": "osint-investigation",
    "public-records": "osint-investigation",
    "username": "sherlock",
    "identity": "sherlock",
    "repository": "oss-forensics",
    "supply-chain": "oss-forensics",
    "codebase": "audit-context-building",
    "source": "audit-context-building",
    "semgrep": "semgrep",
    "codeql": "codeql",
    "sarif": "sarif-parsing",
}
_PHASE_DEFAULTS = {
    Phase.SCOPING: "pentest",
    Phase.RECON: "pentest",
    Phase.VULN_RESEARCH: "pentest",
    Phase.EXPLOITATION: "pentest",
    Phase.POST_EXPLOITATION: "pentest",
    Phase.PRIVESC: "pentest",
    Phase.FLAGS: "pentest",
    Phase.REPORTING: "pentest",
    Phase.RETROSPECTIVE: "fp-check",
}


def _normalise(value: str | None) -> str:
    return "-".join((value or "").strip().lower().replace("_", "-").split())


def validate_catalog(catalog: Iterable[SkillSpec] = CATALOG) -> tuple[str, ...]:
    """Return integrity failures; callers must refuse policy on any failure."""

    errors: list[str] = []
    names: set[str] = set()
    locals_: set[str] = set()
    sources: set[str] = set()
    for spec in catalog:
        name = _normalise(spec.name)
        if not name:
            errors.append("skill catalog contains an empty name")
        elif name in names:
            errors.append(f"duplicate skill name: {spec.name}")
        names.add(name)
        local_name = _normalise(spec.local_name)
        if not local_name:
            errors.append(f"skill {spec.name} has no local name")
        elif local_name in locals_:
            errors.append(f"local-name collision: {spec.local_name}")
        locals_.add(local_name)
        if not spec.source.strip():
            errors.append(f"skill {spec.name} has no source")
        elif spec.source in _EXCLUDED_SOURCES:
            errors.append(f"skill {spec.name} uses excluded source: {spec.source}")
        elif spec.source in sources:
            errors.append(f"duplicate skill source: {spec.source}")
        sources.add(spec.source)
        if spec.trust not in {"bundled", "official", "reviewed-third-party"}:
            errors.append(f"skill {spec.name} has unknown trust level: {spec.trust}")
        if not spec.install_hint.strip():
            errors.append(f"skill {spec.name} has no install hint")
        if spec.approved_bundle_digest and not spec.approved_bundle_digest.startswith("sha256:"):
            errors.append(f"skill {spec.name} has invalid approved bundle digest")
        if spec.trust == "bundled" and spec.digest_required_on_install:
            errors.append(f"bundled skill {spec.name} cannot require a remote install digest")
        if spec.trust != "bundled" and not spec.digest_required_on_install:
            errors.append(f"external skill {spec.name} must require an approved install digest")
    return tuple(errors)


def resolve_skill_route(
    phase: str,
    vulnerability_class: str | None = None,
    candidate_source: str | None = None,
) -> RouteDecision:
    """Resolve one policy route without consulting state or installed skills."""

    catalog_errors = validate_catalog()
    raw_vulnerability = _normalise(vulnerability_class)
    raw_source = _normalise(candidate_source)
    try:
        canonical_phase = normalize_phase(phase)
    except (AttributeError, ValueError):
        return RouteDecision(
            str(phase),
            raw_vulnerability,
            raw_source,
            None,
            (),
            (f"unknown phase: {phase}", *catalog_errors),
        )
    selected = _VULNERABILITY_ROUTES.get(raw_vulnerability)
    if selected is None:
        selected = _SOURCE_ROUTES.get(raw_source)
    if selected is None:
        selected = _PHASE_DEFAULTS[canonical_phase]
    mismatch: list[str] = list(catalog_errors)
    if raw_vulnerability and raw_vulnerability not in _VULNERABILITY_ROUTES:
        mismatch.append(f"unknown vulnerability class: {vulnerability_class}")
    if raw_source and raw_source not in _SOURCE_ROUTES:
        mismatch.append(f"unknown candidate source: {candidate_source}")
    allowed = () if mismatch else (selected,)
    return RouteDecision(
        canonical_phase.value, raw_vulnerability, raw_source, selected, allowed, tuple(mismatch)
    )


def validate_skill_selection(
    selected_skill: str,
    phase: str,
    vulnerability_class: str | None = None,
    candidate_source: str | None = None,
) -> RouteDecision:
    """Resolve and add a fail-closed explanation for an LLM skill mismatch."""

    decision = resolve_skill_route(phase, vulnerability_class, candidate_source)
    selection = _normalise(selected_skill)
    reasons = list(decision.mismatch_reasons)
    if selection not in _CATALOG_BY_NAME:
        reasons.append(f"unknown or unapproved skill: {selected_skill}")
    elif decision.allowed and selection not in decision.allowed:
        reasons.append(f"skill {selected_skill} is not permitted; expected {decision.selected}")
    return RouteDecision(
        decision.phase,
        decision.vulnerability_class,
        decision.candidate_source,
        decision.selected,
        decision.allowed if not reasons else (),
        tuple(reasons),
    )


def catalog_snapshot(repo_root: Path) -> dict[str, object]:
    """Build the Hermes-compatible dependency snapshot payload.

    Hermes ignores the Violin-specific audit metadata, while the later receipt
    layer uses it to ensure an installed external bundle has a recorded digest.
    """

    skills = []
    for spec in CATALOG:
        entry = {
            "identifier": spec.source,
            "category": "security",
            "name": spec.name,
            "local_name": spec.local_name,
            "trust": spec.trust,
            "install_hint": spec.install_hint,
            "approved_bundle_digest": spec.approved_bundle_digest,
            "digest_required_on_install": spec.digest_required_on_install,
        }
        if spec.trust == "bundled":
            entry["path"] = str(repo_root / spec.source.removeprefix("bundled:"))
        skills.append(entry)
    return {"hermes_version": "0.18.0", "skills": skills, "taps": []}
