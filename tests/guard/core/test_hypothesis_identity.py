"""Canonical identifiers must address one hypothesis record."""

import pytest

from plugins.violin_guard.core.engagement import hypotheses


def test_short_heading_id_updates_existing_record(tmp_path):
    path = tmp_path / "hypotheses.md"
    path.write_text(
        "## Active Theories\n\n### H-1: Original\n- **Status:** Candidate\n", encoding="utf-8"
    )
    assert hypotheses.find_by_id(path, "H-001").title == "Original"
    hypotheses.update_hypothesis(path, id="001", title="Updated")
    records = hypotheses.parse_hypotheses(path)
    assert [(record.id, record.title) for record in records] == [("001", "Updated")]


def test_equivalent_heading_ids_reject_update_before_mutation(tmp_path):
    path = tmp_path / "hypotheses.md"
    source = "## Active Theories\n\n### H-1: First\n\n### H-001: Second\n"
    path.write_text(source, encoding="utf-8")
    with pytest.raises(ValueError, match="duplicate IDs"):
        hypotheses.update_hypothesis(path, id="1", title="Updated")
    assert path.read_text(encoding="utf-8") == source
