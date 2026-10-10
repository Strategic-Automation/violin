"""Supersession applies the same phase exit rules as explicit completion."""

import pytest

from plugins.violin_guard.core.engagement import bootstrap, ptt
from plugins.violin_guard.handlers.ptt_handlers import _start_ptt_task


def test_supersession_rejects_incomplete_phase_without_mutation(tmp_path):
    assert bootstrap.init_engagement(tmp_path, host="10.10.10.10") == 0
    path = tmp_path / "state/ptt.md"
    ptt.update_task(path, "PT-030", "[~]", "Research remains incomplete")
    (tmp_path / "hypotheses.md").write_text(
        "# Hypotheses\n\n## Active Theories\n\n### H-001: Unresolved\n- Status: Candidate\n",
        encoding="utf-8",
    )
    before = path.read_bytes()
    with pytest.raises(ValueError, match="unresolved hypotheses"):
        _start_ptt_task(path, ptt.parse_ptt(path), "PT-040", "[~]", "Next task")
    assert path.read_bytes() == before
