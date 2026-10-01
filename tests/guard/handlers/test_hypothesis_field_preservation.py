"""Registered updates preserve fields containing literal HTML or placeholders."""

import json
from pathlib import Path

import pytest

from plugins.violin_guard.core.engagement import bootstrap, hypotheses
from plugins.violin_guard.handlers.ptt_gates import _validate_phase_exit
from plugins.violin_guard.registry import TOOL_DEFINITIONS, _validated_handler


@pytest.mark.parametrize("value", ["echo <token>", "inspect <input name='synthetic'>"])
def test_unrelated_registered_update_preserves_inline_html_fields(tmp_path: Path, value: str):
    assert bootstrap.init_engagement(tmp_path, host="10.10.10.10") == 0
    record = _validated_handler(
        next(tool for tool in TOOL_DEFINITIONS if tool.name == "violin_record_hypothesis")
    )
    fields = {"cheapest_test": value, "test_command": value, "test_response": value}
    created = json.loads(
        record({"eng_dir": str(tmp_path), "id": "001", "title": "Synthetic", **fields})
    )
    assert created["status"] == "ok"
    board = tmp_path / "hypotheses.md"
    before = hypotheses.find_by_id(board, "001")
    assert all(getattr(before, key) == value for key in fields)
    updated = json.loads(record({"eng_dir": str(tmp_path), "id": "001", "rationale": "Updated"}))
    assert updated["status"] == "ok"
    after = hypotheses.find_by_id(board, "001")
    assert all(getattr(after, key) == value for key in fields)
    assert after.rationale == "Updated"


def test_registered_update_preserves_sections_and_ignores_protected_examples(tmp_path: Path):
    assert bootstrap.init_engagement(tmp_path, host="10.10.10.10") == 0
    board = tmp_path / "hypotheses.md"
    protected = (
        "<!--\n### H-990: Comment example\n- Status: Validated\n-->\n\n"
        "```markdown\n### H-991: Fenced example\n- Status: Validated\n```\n\n"
        "### H-001: Synthetic\n- Status: Candidate\n"
        "- Cheapest test: echo <token>\n"
        "- Test Command: echo <token>\n"
        "- Status: Validated <!-- illustrative field -->\n"
    )
    original = board.read_text(encoding="utf-8")
    board.write_text(
        original.replace("## Active Theories", "## Active Theories\n\n" + protected),
        encoding="utf-8",
    )
    assert [item.id for item in hypotheses.parse_hypotheses(board)] == ["001"]
    assert hypotheses.find_by_id(board, "001").status == "Candidate"
    record = _validated_handler(
        next(tool for tool in TOOL_DEFINITIONS if tool.name == "violin_record_hypothesis")
    )
    result = json.loads(record({"eng_dir": str(tmp_path), "id": "001", "rationale": "Updated"}))
    assert result["status"] == "ok"
    persisted = board.read_text(encoding="utf-8")
    assert "### H-990: Comment example" in persisted
    assert "### H-991: Fenced example" in persisted
    for section in ("Observations", "Decoy Trail", "Research Log", "Resolved Theories"):
        assert section in persisted
    parsed = hypotheses.find_by_id(board, "001")
    assert parsed.status == "Candidate"
    assert parsed.cheapest_test == "echo <token>"


def test_rejection_with_inline_placeholder_retains_its_discriminating_test(tmp_path: Path):
    assert bootstrap.init_engagement(tmp_path, host="10.10.10.10") == 0
    evidence = tmp_path / "evidence/synthetic.txt"
    evidence.write_text("Synthetic negative result", encoding="utf-8")
    record = _validated_handler(
        next(tool for tool in TOOL_DEFINITIONS if tool.name == "violin_record_hypothesis")
    )
    response = json.loads(
        record(
            {
                "eng_dir": str(tmp_path),
                "id": "001",
                "title": "Synthetic rejection",
                "status": "Rejected",
                "verification_status": "not_implemented",
                "test_command": "echo <token>",
                "test_response": "Synthetic negative result",
                "rejection_reason": "Synthetic discriminating result",
                "runtime_evidence": "evidence/synthetic.txt",
            }
        )
    )
    assert response["status"] == "ok"
    _validate_phase_exit(tmp_path, "PT-030", "[x]")
