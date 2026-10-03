from __future__ import annotations

from pathlib import Path

import pytest

from plugins.violin_guard.core.engagement import bootstrap, hypotheses
from plugins.violin_guard.handlers.ptt_gates import (
    _validate_phase_exit,
)


def test_vulnerability_research_exit_blocks_unresolved_hypotheses(tmp_path: Path) -> None:
    engagement = tmp_path / "engagement"
    assert bootstrap.init_engagement(engagement, host="10.10.10.10") == 0
    hypotheses.update_hypothesis(
        engagement / "hypotheses.md", id="001", title="Unresolved", status="Likely"
    )
    with pytest.raises(ValueError, match="unresolved hypotheses: H-001"):
        _validate_phase_exit(engagement, "PT-030", "[x]")


def test_vuln_research_exit_blocks_not_implemented_rejection_without_evidence(
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
        "coverage:\n  routes:\n    status: tested\n    evidence_or_reason: 'evidence/recon/probe.txt'\n",
        encoding="utf-8",
    )
    hypotheses.update_hypothesis(
        engagement / "hypotheses.md",
        id="001",
        title="Admin login check",
        status="Rejected",
        verification_status="not_implemented",
        test_command="N/A - placeholder hypothesis",
        test_response="never executed",
        rejection_reason="placeholder superseded",
        cheapest_test="Login as admin (admin/admin)",
    )
    with pytest.raises(
        ValueError, match="rejections that never ran their cheapest discriminating test"
    ):
        _validate_phase_exit(engagement, "PT-030", "[x]")


def test_vuln_research_exit_accepts_surface_mapping_rejection_with_evidence(
    tmp_path: Path,
) -> None:
    """Known-good pattern: a recon surface-mapping hypothesis rejected as
    not_implemented is fine when it cites real bundle/probe evidence."""
    engagement = tmp_path / "engagement"
    assert bootstrap.init_engagement(engagement, host="10.10.10.10") == 0
    scope = engagement / "scope" / "scope.yaml"
    scope.write_text(
        scope.read_text(encoding="utf-8") + "\nengagement:\n  audit_mode: true\n",
        encoding="utf-8",
    )
    matrix = engagement / "state" / "coverage-matrix.yaml"
    matrix.write_text(
        "coverage:\n  routes:\n    status: tested\n    evidence_or_reason: 'evidence/recon/probe.txt'\n",
        encoding="utf-8",
    )
    hypotheses.update_hypothesis(
        engagement / "hypotheses.md",
        id="001",
        title="API surface enumeration from JS bundle",
        status="Rejected",
        verification_status="not_implemented",
        test_command="GET /api/v1/products/, /testimonials/",
        test_response="surface mapped, see evidence",
        rejection_reason="not a vulnerability claim",
        evidence="evidence/recon/recon_bundle.js",
        cheapest_test="Probe each derived endpoint",
    )
    _validate_phase_exit(engagement, "PT-030", "[x]")  # no exception


def test_validated_hypothesis_rejects_escaping_or_empty_evidence(tmp_path: Path) -> None:
    engagement = tmp_path / "engagement"
    assert bootstrap.init_engagement(engagement, host="10.10.10.10") == 0
    board = engagement / "hypotheses.md"
    hypotheses.update_hypothesis(board, id="001", title="Candidate", status="Candidate")
    original = board.read_text(encoding="utf-8")
    outside = engagement / "outside.txt"
    outside.write_text("proof\n", encoding="utf-8")
    with pytest.raises(ValueError, match="beneath evidence"):
        hypotheses.update_hypothesis(
            board,
            id="001",
            status="Validated",
            runtime_evidence="evidence/../outside.txt",
        )
    assert board.read_text(encoding="utf-8") == original

    empty = engagement / "evidence" / "exploitation" / "empty.txt"
    empty.parent.mkdir(parents=True, exist_ok=True)
    empty.write_text("", encoding="utf-8")
    with pytest.raises(ValueError, match="must not be empty"):
        hypotheses.update_hypothesis(
            board,
            id="001",
            status="Validated",
            runtime_evidence="evidence/exploitation/empty.txt",
        )


def test_validated_hypothesis_accepts_multiple_runtime_evidence_files(tmp_path: Path) -> None:
    engagement = tmp_path / "engagement"
    assert bootstrap.init_engagement(engagement, host="10.10.10.10") == 0
    board = engagement / "hypotheses.md"
    for filename in ("request.txt", "response.txt"):
        path = engagement / "evidence" / "vuln-research" / filename
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("proof\n", encoding="utf-8")

    updated = hypotheses.update_hypothesis(
        board,
        id="001",
        title="Two-artifact proof",
        status="Validated",
        runtime_evidence=(
            "evidence/vuln-research/request.txt, evidence/vuln-research/response.txt"
        ),
    )

    assert updated.runtime_evidence.endswith("evidence/vuln-research/response.txt")
