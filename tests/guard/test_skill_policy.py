"""Pure tests for the v3 skill selection policy."""

from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path

import pytest

from plugins.violin_guard.phases import Phase
from plugins.violin_guard.skill_policy import (
    CATALOG,
    SkillSpec,
    catalog_snapshot,
    resolve_skill_route,
    validate_catalog,
    validate_skill_selection,
)


@pytest.mark.parametrize("phase", list(Phase))
def test_every_phase_has_one_deterministic_default_route(phase: Phase) -> None:
    decision = resolve_skill_route(phase.value)

    assert decision.selected
    assert decision.allowed == (decision.selected,)
    assert not decision.mismatch_reasons


@pytest.mark.parametrize(
    ("vulnerability_class", "expected"),
    [
        ("SQLi", "web-attacks"),
        ("xss", "web-attacks"),
        ("ssrf", "web-attacks"),
        ("command injection", "web-attacks"),
        ("path traversal", "web-attacks"),
        ("JWT", "access-control"),
        ("IDOR", "access-control"),
        ("auth bypass", "access-control"),
        ("broken access control", "access-control"),
        ("broken object level authorization", "access-control"),
        ("server side request forgery", "web-attacks"),
        ("cross site scripting", "web-attacks"),
        ("source analysis", "audit-context-building"),
        ("static analysis", "semgrep"),
        ("sarif", "sarif-parsing"),
        ("false positive", "fp-check"),
    ],
)
def test_vulnerability_class_routes_are_deterministic(
    vulnerability_class: str, expected: str
) -> None:
    decision = resolve_skill_route("vuln-research", vulnerability_class)

    assert decision.selected == expected
    assert decision.allowed == (expected,)


@pytest.mark.parametrize(
    ("candidate_source", "expected"),
    [
        ("domain", "domain-intel"),
        ("osint", "osint-investigation"),
        ("username", "sherlock"),
        ("repository", "oss-forensics"),
        ("codebase", "audit-context-building"),
        ("codeql", "codeql"),
    ],
)
def test_candidate_source_routes_are_deterministic(candidate_source: str, expected: str) -> None:
    decision = resolve_skill_route("recon", candidate_source=candidate_source)

    assert decision.selected == expected
    assert decision.allowed == (expected,)


def test_unknown_policy_input_fails_closed() -> None:
    decision = resolve_skill_route("vuln-research", "deserialization")

    assert decision.selected == "pentest"
    assert not decision.allowed
    assert any(
        "unknown vulnerability class: deserialization; valid classes are:" in r
        for r in decision.mismatch_reasons
    )


def test_unknown_candidate_source_returns_accepted_values_and_routes() -> None:
    decision = resolve_skill_route("recon", candidate_source="internet-search")

    assert not decision.allowed
    message = "\n".join(decision.mismatch_reasons)
    assert "accepted normalized values and routes" in message
    assert "source -> audit-context-building" in message
    assert "username -> sherlock" in message


@pytest.mark.parametrize("selected", ["godmode", "web-pentest", "yayalingo", "hack-skills"])
def test_unapproved_or_competing_skills_are_rejected(selected: str) -> None:
    decision = validate_skill_selection(selected, "recon")

    assert not decision.allowed
    assert any("unknown or unapproved" in reason for reason in decision.mismatch_reasons)


def test_selection_must_match_the_vulnerability_route() -> None:
    decision = validate_skill_selection("pentest", "vuln-research", "sqli")

    assert not decision.allowed
    assert decision.selected == "web-attacks"
    assert "not permitted" in decision.mismatch_reasons[-1]


def test_skill_mismatch_explains_the_route_basis_and_exact_fix() -> None:
    decision = validate_skill_selection("pentest", "vuln-research", "jwt")

    message = decision.mismatch_reasons[-1]
    assert "expected 'access-control'" in message
    assert "vulnerability_class 'jwt'" in message
    assert "Set skill='access-control'" in message


@pytest.mark.parametrize(
    "replacement, expected",
    [
        (replace(CATALOG[0], name="web-attacks"), "duplicate skill name"),
        (replace(CATALOG[0], local_name="web-attacks"), "local-name collision"),
        (replace(CATALOG[0], source=""), "has no source"),
        (replace(CATALOG[0], source="official/security/godmode"), "uses excluded source"),
    ],
)
def test_catalog_integrity_fails_closed(replacement: SkillSpec, expected: str) -> None:
    catalog = (replacement, *CATALOG[1:])

    assert any(expected in error for error in validate_catalog(catalog))


def test_snapshot_is_hermes_compatible_and_has_required_audit_metadata() -> None:
    root = Path(__file__).resolve().parents[2]
    checked_in = json.loads((root / "skills.snapshot.json").read_text(encoding="utf-8"))
    generated = catalog_snapshot(root)

    assert checked_in["hermes_version"] == generated["hermes_version"]
    assert [entry["identifier"] for entry in checked_in["skills"]] == [
        entry["identifier"] for entry in generated["skills"]
    ]
    assert len(checked_in["skills"]) == len(CATALOG)
    for entry in checked_in["skills"]:
        assert {
            "identifier",
            "category",
            "name",
            "trust",
            "install_hint",
            "digest_required_on_install",
        } <= entry.keys()
        assert entry["category"] == "security"
