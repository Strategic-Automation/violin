"""Approved skill catalog and installation provenance."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path


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
        "web-app",
        "bundled:skills/web-app",
        "web-app",
        "bundled",
        "included with Violin",
        None,
    ),
    SkillSpec(
        "identity-auth",
        "bundled:skills/identity-auth",
        "identity-auth",
        "bundled",
        "included with Violin",
        None,
    ),
    SkillSpec(
        "api-testing",
        "bundled:skills/api-testing",
        "api-testing",
        "bundled",
        "included with Violin",
        None,
    ),
    SkillSpec(
        "business-logic",
        "bundled:skills/business-logic",
        "business-logic",
        "bundled",
        "included with Violin",
        None,
    ),
    SkillSpec(
        "llm-security",
        "bundled:skills/llm-security",
        "llm-security",
        "bundled",
        "included with Violin",
        None,
    ),
    SkillSpec(
        "misconfig",
        "bundled:skills/misconfig",
        "misconfig",
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


def _normalize(value: str | None) -> str:
    return "-".join((value or "").strip().lower().replace("_", "-").split())


def skill_spec(name: str) -> SkillSpec | None:
    """Return catalog provenance and installation guidance for a skill."""
    return _CATALOG_BY_NAME.get(_normalize(name))


def validate_catalog(catalog: Iterable[SkillSpec] = CATALOG) -> tuple[str, ...]:
    """Return integrity failures; callers must refuse policy on any failure."""

    errors: list[str] = []
    names: set[str] = set()
    locals_: set[str] = set()
    sources: set[str] = set()
    for spec in catalog:
        name = _normalize(spec.name)
        if not name:
            errors.append("skill catalog contains an empty name")
        elif name in names:
            errors.append(f"duplicate skill name: {spec.name}")
        names.add(name)
        local_name = _normalize(spec.local_name)
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
    return {"hermes_version": "0.21.5", "skills": skills, "taps": []}
