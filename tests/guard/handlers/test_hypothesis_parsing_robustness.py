"""Hypothesis records follow Markdown block and section boundaries."""

from __future__ import annotations

from pathlib import Path

import pytest

from plugins.violin_guard.core import hypotheses


def _board(text: str, path: Path) -> Path:
    path.write_text(text, encoding="utf-8", newline="")
    return path


def test_parse_reads_only_canonical_records_in_active_theories(tmp_path: Path) -> None:
    path = _board(
        "# Board\n\n"
        "## Active Theories\n\n"
        "### H-001: SQL injection\n- **Status:** Validated (conf 0.9)\n\n"
        "## Observations\n\n"
        "### H-002: This is an observation heading\n- **Status:** Candidate\n",
        tmp_path / "hypotheses.md",
    )

    records = hypotheses.parse_hypotheses(path)

    assert [(record.id, record.canonical_status()) for record in records] == [("001", "Validated")]


def test_parse_ignores_records_inside_fences_and_comments(tmp_path: Path) -> None:
    path = _board(
        "# Board\n\n## Active Theories\n\n"
        "```markdown\n### H-998: Example only\n- **Status:** Validated\n```\n\n"
        "<!--\n### H-999: Comment example\n- **Status:** Validated\n-->\n\n"
        "### H-001: Real record\n- **Status:** Candidate\n",
        tmp_path / "hypotheses.md",
    )

    assert [record.id for record in hypotheses.parse_hypotheses(path)] == ["001"]


def test_parse_rejects_malformed_record_heading_in_active_section(tmp_path: Path) -> None:
    path = _board(
        "# Board\n\n## Active Theories\n\n### H-not-a-number: malformed\n",
        tmp_path / "hypotheses.md",
    )

    with pytest.raises(ValueError, match="expected ### H-<number>"):
        hypotheses.parse_hypotheses(path)
