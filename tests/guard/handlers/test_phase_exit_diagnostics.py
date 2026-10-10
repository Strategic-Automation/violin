from __future__ import annotations

from pathlib import Path

import pytest

from plugins.violin_guard.core.engagement import bootstrap, hypotheses
from plugins.violin_guard.handlers.ptt_gates import (
    _validate_phase_exit,
)


def test_vuln_research_exit_batches_all_preconditions_in_one_error(tmp_path: Path) -> None:
    """The close gate must surface methodology, coverage, AND hypothesis failures
    together — not one at a time — so the agent fixes them in a single pass."""
    engagement = tmp_path / "engagement"
    assert bootstrap.init_engagement(engagement, host="10.10.10.10") == 0
    scope = engagement / "scope" / "scope.yaml"
    scope.write_text(
        scope.read_text(encoding="utf-8")
        + "\nengagement:\n  audit_mode: true\n  require_methodology_gates: true\n"
        "  coverage_obligations:\n    - POST /api/route_a\n",
        encoding="utf-8",
    )
    # 1. methodology-gates file missing
    gates = engagement / "state" / "methodology-gates.yaml"
    gates.unlink()
    # 2. coverage matrix has a bad cell (status outside the vocabulary)
    matrix = engagement / "state" / "coverage-matrix.yaml"
    matrix.write_text(
        "coverage:\n  route_a:\n    status: pending\n    evidence_or_reason: ''\n",
        encoding="utf-8",
    )
    # 3. an unresolved hypothesis
    hypotheses.update_hypothesis(
        engagement / "hypotheses.md", id="001", title="Unresolved", status="Likely"
    )
    with pytest.raises(ValueError) as exc:
        _validate_phase_exit(engagement, "PT-030", "[x]")
    msg = str(exc.value)
    # All three preconditions appear in the SAME error.
    assert "methodology-gates.yaml exists" in msg
    assert "undispositioned coverage" in msg
    assert "unresolved hypotheses: H-001" in msg
