"""Hypothesis-board rewrite integrity: the writer owns records and nothing else.

The writer used to derive structure with its own regex scan while the reader used
``_parse_heading`` plus HTML-comment tracking. The two disagreed in two ways, both of
which destroyed authored bytes:

1. A board whose records were written with ``## H-00N`` headings was read as having no
   records at all, so the whole file became the "header" and every record was appended
   again. The board doubled, ``update_hypothesis``'s own integrity check then refused
   the write (two records for one id), the phase could never be set, and the phase gate
   blocked every target command for the rest of the run.
2. The canonical template documents the record format inside an HTML comment that
   contains an example ``### H-001: <short title>`` heading. The writer took that
   commented example for the first record and replaced everything up to the next
   ``##`` section, deleting the format comment (and leaving the ``<!--`` unterminated).

Both are one defect: the writer held a second, narrower model of the file's structure.
These tests pin the invariant — a rewrite changes the records and nothing else.
"""

from __future__ import annotations

from pathlib import Path

from plugins.violin_guard.core import hypotheses

ROOT = Path(__file__).resolve().parents[3]


def _canonical_board(path: Path) -> Path:
    path.write_text(
        "# Hypothesis Board\n\n"
        "## Engagement\n"
        "Target: https://duck-store.escape.tech\n\n"
        "## Active Theories\n\n"
        "### H-001: Unauthenticated user enumeration + PII disclosure\n"
        "**Target:** GET /api/v1/users/\n"
        "**Status:** Candidate\n\n"
        "### H-002: Privilege escalation via mass-assignment\n"
        "**Target:** PUT /api/v1/users/me/profile\n"
        "**Status:** Candidate\n",
        encoding="utf-8",
    )
    return path


def test_rewrite_does_not_duplicate_canonical_records(tmp_path: Path) -> None:
    board = _canonical_board(tmp_path / "hypotheses.md")
    records = hypotheses.parse_hypotheses(board)
    assert [record.id for record in records] == ["001", "002"]

    hypotheses._rewrite_hypotheses(board, records)

    after = hypotheses.parse_hypotheses(board)
    assert [record.id for record in after] == ["001", "002"]
    text = board.read_text(encoding="utf-8")
    assert text.count("H-001:") == 1
    assert text.count("H-002:") == 1


def test_update_phase_succeeds_on_canonical_board(tmp_path: Path) -> None:
    board = _canonical_board(tmp_path / "hypotheses.md")

    updated = hypotheses.update_hypothesis(board, id="H-002", phase="VULN_RESEARCH")

    assert updated.phase == "VULN_RESEARCH"
    text = board.read_text(encoding="utf-8")
    assert "**Phase:** VULN_RESEARCH" in text
    after = hypotheses.parse_hypotheses(board)
    assert len(after) == 2
    assert [record.id for record in after].count("002") == 1


def test_canonical_template_keeps_its_authoring_comment(tmp_path: Path) -> None:
    template = (ROOT / "skills" / "pentest" / "templates" / "hypothesis-board.md").read_text(
        encoding="utf-8"
    )
    board = tmp_path / "hypotheses.md"
    board.write_text(template, encoding="utf-8")

    hypotheses.update_hypothesis(
        board, id="001", title="Command injection in search", status="Candidate"
    )

    text = board.read_text(encoding="utf-8")
    # The commented format example is authored content: it must survive the write.
    assert "<!--" in text
    assert "-->" in text
    assert "- **Verification Status:**" in text
    assert "### H-001: Command injection in search" in text
    for section in (
        "## Active Theories",
        "## Observations (ungrouped)",
        "## Decoy Trail",
        "## Research Log",
    ):
        assert section in text
    assert len(hypotheses.parse_hypotheses(board)) == 1


def test_rewrite_does_not_read_records_outside_active_section(tmp_path: Path) -> None:
    board = tmp_path / "hypotheses.md"
    board.write_text(
        "# Hypothesis Board\n\n"
        "## Active Theories\n\n"
        "### H-001: SQLi in filter\n"
        "- **Status:** Candidate\n\n"
        "## Observations (ungrouped)\n\n"
        "- **OBS-001:** error text leaked — /filter — 2026-09-20 — medium\n\n"
        "### H-002: Open redirect\n"
        "- **Status:** Candidate\n",
        encoding="utf-8",
    )
    records = hypotheses.parse_hypotheses(board)

    hypotheses._rewrite_hypotheses(board, records)

    text = board.read_text(encoding="utf-8")
    assert "## Observations (ungrouped)" in text
    assert "OBS-001" in text
    assert text.count("H-001:") == 1
    assert text.count("H-002:") == 1
    assert [record.id for record in hypotheses.parse_hypotheses(board)] == ["001"]
    assert "### H-002: Open redirect" in text


def test_rewrite_is_idempotent(tmp_path: Path) -> None:
    board = tmp_path / "hypotheses.md"
    board.write_text(
        "# Hypothesis Board\n\n## Active Theories\n\n"
        "### H-001: SSRF via fetch-url\n- **Status:** Candidate\n- **Phase:** RECON\n",
        encoding="utf-8",
    )
    records = hypotheses.parse_hypotheses(board)

    hypotheses._rewrite_hypotheses(board, records)
    once = board.read_text(encoding="utf-8")
    hypotheses._rewrite_hypotheses(board, hypotheses.parse_hypotheses(board))

    assert board.read_text(encoding="utf-8") == once


def test_new_record_lands_in_host_section_before_following_sections(tmp_path: Path) -> None:
    board = tmp_path / "hypotheses.md"
    board.write_text(
        "# Hypothesis Board\n\n"
        "## Active Theories\n\n"
        "<!-- format example ### H-001: <short title> -->\n\n"
        "## Observations (ungrouped)\n\n"
        "## Decoy Trail (killed approaches — do NOT re-enter)\n",
        encoding="utf-8",
    )

    hypotheses.update_hypothesis(board, id="001", title="Open redirect", status="Candidate")

    text = board.read_text(encoding="utf-8")
    assert text.index("### H-001: Open redirect") < text.index("## Observations (ungrouped)")
    assert "format example" in text
    assert "## Active Theories" in text


def test_update_preserves_crlf_and_non_record_sections(tmp_path: Path) -> None:
    board = tmp_path / "hypotheses.md"
    original = (
        "# Board\r\n\r\n"
        "## Active Theories\r\n\r\n"
        "### H-001: Candidate\r\n"
        "- **Status:** Candidate\r\n\r\n"
        "## Observations\r\n\r\n"
        "- Keep this authored observation.\r\n"
    )
    board.write_bytes(original.encode("utf-8"))

    hypotheses.update_hypothesis(board, id="001", title="Updated candidate", status="Likely")

    updated = board.read_bytes().decode("utf-8")
    assert "### H-001: Updated candidate\r\n- **Status:** Likely\r\n" in updated
    assert "## Observations\r\n\r\n- Keep this authored observation.\r\n" in updated
    assert "\n" not in updated.replace("\r\n", "")
