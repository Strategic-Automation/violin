from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from plugins.violin_guard.core.engagement import bootstrap
from plugins.violin_guard.core.engagement.disposition_policy import evaluate_dispositions
from plugins.violin_guard.handlers.ptt_gates import (
    _validate_phase_exit,
)


def test_audit_mode_vulnerability_research_exit_requires_dispositioned_matrix(
    tmp_path: Path,
) -> None:
    engagement = tmp_path / "engagement"
    assert bootstrap.init_engagement(engagement, host="10.10.10.10") == 0
    scope = engagement / "scope" / "scope.yaml"
    scope.write_text(
        scope.read_text(encoding="utf-8") + "\nengagement:\n  audit_mode: true\n",
        encoding="utf-8",
    )
    matrix = engagement / "state" / "coverage-matrix.yaml"
    matrix.write_text(
        "coverage:\n  routes:\n    status: pending\n    evidence_or_reason: ''\n",
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="undispositioned coverage: routes"):
        _validate_phase_exit(engagement, "PT-030", "[x]")


def test_bootstrap_pre_keys_the_coverage_matrix_from_declared_obligations(
    tmp_path: Path,
) -> None:
    """#123: a bootstrapped engagement starts from its real obligation keys, not placeholders."""
    engagement = tmp_path / "engagement"
    scope_path = engagement / "scope" / "scope.yaml"
    scope_path.parent.mkdir(parents=True, exist_ok=True)
    scope_path.write_text(
        yaml.safe_dump(
            {
                "targets": {"ip_addresses": ["10.10.10.10"], "in_scope_urls": []},
                "rules_of_engagement": {"allowed_actions": ["recon"], "forbidden_actions": []},
                "engagement": {
                    "coverage_obligations": ["POST /api/v1/auth/login", "GET /api/users"]
                },
                "authorisation": {"confirmed": True},
            },
            sort_keys=False,
        ),
        encoding="utf-8",
    )

    assert bootstrap.init_engagement(engagement, host="10.10.10.10") == 0

    matrix = yaml.safe_load(
        (engagement / "state" / "coverage-matrix.yaml").read_text(encoding="utf-8")
    )
    coverage = matrix["coverage"]
    assert set(coverage) == {"post /api/v1/auth/login", "get /api/users"}
    assert {cell["status"] for cell in coverage.values()} == {"pending"}


def test_seeded_coverage_keys_match_the_close_gate_vocabulary() -> None:
    """#123: the writer (bootstrap) and the reader (close gate) agree on the keys, and an
    unrecognised key names the accepted vocabulary instead of surfacing at close."""
    obligations = ["POST /api/v1/auth/login"]
    seeded = {"post /api/v1/auth/login": {"status": "pending", "evidence_or_reason": ""}}
    assert not evaluate_dispositions(seeded, obligations=obligations).unrecognized_entries

    errors = evaluate_dispositions(
        {"post /api/v1/auth/other": {"status": "pending", "evidence_or_reason": ""}},
        obligations=obligations,
    ).unrecognized_entries
    assert errors and "accepted keys: post /api/v1/auth/login" in errors[0]


def test_vuln_research_exit_requires_evidence_for_not_applicable_coverage(
    tmp_path: Path,
) -> None:
    engagement = tmp_path / "engagement"
    assert bootstrap.init_engagement(engagement, host="10.10.10.10") == 0
    scope = engagement / "scope" / "scope.yaml"
    scope.write_text(
        scope.read_text(encoding="utf-8") + "\nengagement:\n  audit_mode: true\n",
        encoding="utf-8",
    )
    matrix = engagement / "state" / "coverage-matrix.yaml"
    matrix.write_text(
        "coverage:\n"
        "  rate_limits:\n"
        "    status: not_applicable\n"
        "    evidence_or_reason: 'no rate-limit behavior observed on target'\n",
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="not_applicable without evidence file"):
        _validate_phase_exit(engagement, "PT-030", "[x]")


def test_coverage_scoring_and_phase_close_share_disposition_policy(tmp_path: Path) -> None:
    from benchmark.score import _disposition_metric

    engagement = tmp_path / "engagement"
    assert bootstrap.init_engagement(engagement, host="10.10.10.10") == 0
    scope = engagement / "scope" / "scope.yaml"
    scope.write_text(
        scope.read_text(encoding="utf-8")
        + "\nengagement:\n  audit_mode: true\n  coverage_obligations:\n"
        "    - POST /api/v1/auth/login\n",
        encoding="utf-8",
    )
    matrix = engagement / "state" / "coverage-matrix.yaml"
    matrix.write_text(
        "coverage:\n"
        "  'post /api/v1/auth/login':\n"
        "    status: tested\n"
        "    evidence_or_reason: 'looks fine'\n",
        encoding="utf-8",
    )

    metric = _disposition_metric(
        matrix,
        "coverage",
        obligations=["POST /api/v1/auth/login"],
    )
    assert metric["complete"] is False
    with pytest.raises(ValueError, match="tested without evidence"):
        _validate_phase_exit(engagement, "PT-030", "[x]")

    matrix.write_text(
        "coverage:\n"
        "  'post /api/v1/auth/login':\n"
        "    status: tested\n"
        "    evidence_or_reason: 'evidence/vuln-research/login.txt'\n",
        encoding="utf-8",
    )
    metric = _disposition_metric(
        matrix,
        "coverage",
        obligations=["POST /api/v1/auth/login"],
    )
    assert metric == {"complete": True, "completed": 1, "total": 1, "percent": 100.0}


def test_bootstrap_creates_coverage_matrix_template(tmp_path: Path) -> None:
    engagement = tmp_path / "engagement"
    assert bootstrap.init_engagement(engagement, host="10.10.10.10") == 0
    matrix = engagement / "state" / "coverage-matrix.yaml"
    assert matrix.is_file()
    text = matrix.read_text(encoding="utf-8")
    assert "coverage:" in text
    assert "status:" in text
    assert "evidence_or_reason:" in text


def test_coverage_close_error_prints_exact_key_and_example(tmp_path: Path) -> None:
    engagement = tmp_path / "engagement"
    assert bootstrap.init_engagement(engagement, host="10.10.10.10") == 0
    scope = engagement / "scope" / "scope.yaml"
    scope.write_text(
        scope.read_text(encoding="utf-8")
        + "\nengagement:\n  audit_mode: true\n  coverage_obligations:\n    - POST /api/v1/auth/login\n",
        encoding="utf-8",
    )
    matrix = engagement / "state" / "coverage-matrix.yaml"
    matrix.write_text(
        "coverage:\n  routes:\n    post_api_v1_auth_login:\n"
        "      status: tested\n      evidence_or_reason: 'evidence/x.txt'\n",
        encoding="utf-8",
    )
    with pytest.raises(ValueError) as exc:
        _validate_phase_exit(engagement, "PT-030", "[x]")
    msg = str(exc.value)
    assert "post /api/v1/auth/login" in msg  # names the first missing obligation
    assert "exact lowercased obligation" in msg.lower()  # key-format rule
    assert "status: tested" in msg  # example cell shown


def test_vuln_research_coverage_error_teaches_remediation(tmp_path: Path) -> None:
    """The undispositioned-coverage error must name a fix, not just list failures."""
    engagement = tmp_path / "engagement"
    assert bootstrap.init_engagement(engagement, host="10.10.10.10") == 0
    scope = engagement / "scope" / "scope.yaml"
    scope.write_text(
        scope.read_text(encoding="utf-8")
        + "\nengagement:\n  audit_mode: true\n  coverage_obligations:\n    - POST /api/route_a\n",
        encoding="utf-8",
    )
    matrix = engagement / "state" / "coverage-matrix.yaml"
    matrix.write_text(
        "coverage:\n  route_a:\n    status: tested\n    evidence_or_reason: 'no artifact cited'\n",
        encoding="utf-8",
    )
    with pytest.raises(ValueError) as exc:
        _validate_phase_exit(engagement, "PT-030", "[x]")
    msg = str(exc.value)
    assert "coverage-matrix cell" in msg  # which obligation never got a cell
    assert "how to fix" in msg  # the gate teaches the remediation
    assert "'not_applicable' cells" in msg


def test_vuln_research_exit_blocks_uncharted_scored_challenges(tmp_path: Path) -> None:
    """Coverage completeness: every in-scope endpoint needs a matrix cell.

    Client-provided in-scope endpoints (fetch-url, login) must map to a
    coverage-matrix cell — self-declared 'tested'/N/A coverage of related
    categories is not enough.
    """
    engagement = tmp_path / "engagement"
    assert bootstrap.init_engagement(engagement, host="10.10.10.10") == 0
    scope = engagement / "scope" / "scope.yaml"
    scope.write_text(
        scope.read_text(encoding="utf-8")
        + "\nengagement:\n  audit_mode: true\n  coverage_obligations:\n    - GET /api/v1/uploads/fetch-url\n    - POST /api/v1/auth/login\n",
        encoding="utf-8",
    )
    matrix = engagement / "state" / "coverage-matrix.yaml"
    matrix.write_text(
        "coverage:\n  routes:\n    status: tested\n    evidence_or_reason: 'evidence/recon/probe.txt'\n",
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="no coverage-matrix cell"):
        _validate_phase_exit(engagement, "PT-030", "[x]")


def test_vuln_research_exit_rejects_challenge_alias_despite_artifact(tmp_path: Path) -> None:
    engagement = tmp_path / "engagement"
    assert bootstrap.init_engagement(engagement, host="10.10.10.10") == 0
    scope = engagement / "scope" / "scope.yaml"
    scope.write_text(
        scope.read_text(encoding="utf-8")
        + "\nengagement:\n  audit_mode: true\n  coverage_obligations:\n    - POST /api/v1/auth/login\n",
        encoding="utf-8",
    )
    matrix = engagement / "state" / "coverage-matrix.yaml"
    matrix.write_text(
        "coverage:\n  no-rate-limiting:\n    status: not_applicable\n    evidence_or_reason: 'evidence/vuln-research/rate_na.txt - 429 never observed; POST /api/v1/auth/login probed 20x'\n",
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="unrecognised obligation key"):
        _validate_phase_exit(engagement, "PT-030", "[x]")


def test_vuln_research_exit_accepts_evidence_backed_not_applicable(tmp_path: Path) -> None:
    engagement = tmp_path / "engagement"
    assert bootstrap.init_engagement(engagement, host="10.10.10.10") == 0
    scope = engagement / "scope" / "scope.yaml"
    scope.write_text(
        scope.read_text(encoding="utf-8") + "\nengagement:\n  audit_mode: true\n",
        encoding="utf-8",
    )
    matrix = engagement / "state" / "coverage-matrix.yaml"
    matrix.write_text(
        "coverage:\n"
        "  rate_limits:\n"
        "    status: not_applicable\n"
        "    evidence_or_reason: 'probed 10x in evidence/recon/rate_probe.txt; no 429'\n",
        encoding="utf-8",
    )
    _validate_phase_exit(engagement, "PT-030", "[x]")  # no exception


def test_vuln_research_exit_blocks_aspirational_tested_narrative(tmp_path: Path) -> None:
    """'tested' without an artifact reference is aspirational, not proof."""
    engagement = tmp_path / "engagement"
    assert bootstrap.init_engagement(engagement, host="10.10.10.10") == 0
    scope = engagement / "scope" / "scope.yaml"
    scope.write_text(
        scope.read_text(encoding="utf-8") + "\nengagement:\n  audit_mode: true\n",
        encoding="utf-8",
    )
    matrix = engagement / "state" / "coverage-matrix.yaml"
    matrix.write_text(
        "coverage:\n  redirects:\n    status: tested\n    evidence_or_reason: 'no open redirect parameter found'\n",
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="tested without evidence/FIND/hypothesis"):
        _validate_phase_exit(engagement, "PT-030", "[x]")
