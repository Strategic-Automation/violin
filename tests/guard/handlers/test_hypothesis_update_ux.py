"""Regression tests for hypothesis board updates."""

from __future__ import annotations

from pathlib import Path

from plugins.violin_guard.core.engagement import hypotheses

ROOT = Path(__file__).resolve().parents[3]


def test_update_hypothesis_supports_discipline_fields(tmp_path: Path) -> None:
    hyp_file = tmp_path / "hypotheses.md"
    hyp_file.write_text(
        "# Hypothesis Board\n\n## Active Theories\n\n",
        encoding="utf-8",
    )
    h = hypotheses.update_hypothesis(
        hyp_file,
        id="001",
        title="SQLi in authentication form",
        status="Candidate",
        confidence="0.8",
        timebox="4 tool batches",
        cheapest_test="' OR 1=1 --",
        kill_criteria="Response status 404 or no error output",
        next_step="Run sqlmap probe",
    )
    assert h.confidence == "0.8"
    assert h.timebox == "4 tool batches"
    assert h.cheapest_test == "' OR 1=1 --"
    assert h.kill_criteria == "Response status 404 or no error output"
    assert h.next_step == "Run sqlmap probe"

    parsed = hypotheses.parse_hypotheses(hyp_file)
    assert len(parsed) == 1
    assert parsed[0].confidence == "0.8"
    assert parsed[0].cheapest_test == "' OR 1=1 --"

    text = hyp_file.read_text(encoding="utf-8")
    assert "- **Confidence:** 0.8" in text
    assert "- **Timebox:** 4 tool batches" in text
    assert "- **Cheapest test:** ' OR 1=1 --" in text
    assert "- **Kill criteria:** Response status 404 or no error output" in text


def test_update_hypothesis_preserves_board_sections(tmp_path: Path) -> None:
    template_path = ROOT / "skills" / "pentest" / "templates" / "hypothesis-board.md"
    hyp_file = tmp_path / "hypotheses.md"
    hyp_file.write_text(template_path.read_text(encoding="utf-8"), encoding="utf-8")

    h = hypotheses.update_hypothesis(
        hyp_file,
        id="001",
        title="Command injection in search endpoint",
        status="Candidate",
    )
    assert h.id == "001"
    text = hyp_file.read_text(encoding="utf-8")
    assert "## Active Theories" in text
    assert "### H-001: Command injection in search endpoint" in text
    assert "## Observations (ungrouped)" in text
    assert "## Investigation Chains" in text
    assert "## Decoy Trail (killed approaches — do NOT re-enter)" in text
    assert "## Research Log" in text
    assert "## Resolved Theories" in text


def test_update_hypothesis_keeps_distinct_ids_isolated(tmp_path: Path) -> None:
    hyp_file = tmp_path / "hypotheses.md"
    hyp_file.write_text("# Hypothesis Board\n\n", encoding="utf-8")
    evidence = tmp_path / "evidence" / "executions" / "access-control.json"
    evidence.parent.mkdir(parents=True)
    evidence.write_text('{"status":"completed"}\n', encoding="utf-8")
    hypotheses.update_hypothesis(
        hyp_file,
        id="H-021",
        title="Existing access-control finding",
        status="Validated",
        runtime_evidence="evidence/executions/access-control.json",
    )
    hypotheses.update_hypothesis(
        hyp_file,
        id="H-030",
        title="CVE research candidate",
        status="Candidate",
        cve_research="Vendor advisory checked; no relevant CVE.",
    )

    records = {item.id: item for item in hypotheses.parse_hypotheses(hyp_file)}
    assert set(records) == {"021", "030"}
    assert records["021"].title == "Existing access-control finding"
    assert records["021"].status == "Validated"
    assert records["030"].title == "CVE research candidate"
    assert records["030"].cve_research.startswith("Vendor advisory")
