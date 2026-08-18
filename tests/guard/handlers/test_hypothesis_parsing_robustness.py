"""Tests for hypothesis-board parsing robustness (heading depth + status suffix).

Fixes two silent-drop defects that read genuine Validated hypotheses as untested:
1. A hypothesis row written at `## H-001:` (double-hash) was dropped by a parser
   that only accepted `### H-001:`. Any rows a model wrote at another heading
   depth silently vanished -> scored as untested/0-proof.
2. A status of "Validated (conf 0.9)" or "Validated (stored raw)" was not
   canonicalized, so the record failed canonical-status checks.
"""

from __future__ import annotations

from pathlib import Path

from plugins.violin_guard.core import hypotheses


def _board(text: str, path: Path) -> Path:
    path.write_text(text, encoding="utf-8")
    return path


def test_parse_accepts_double_hash_heading(tmp_path: Path) -> None:
    p = _board(
        "## H-001: Horizontal IDOR\n- **Status:** Validated\n- **Phase:** EXPLOITATION\n",
        tmp_path / "hypotheses.md",
    )
    recs = hypotheses.parse_hypotheses(p)
    assert len(recs) == 1
    assert recs[0].id == "001"
    assert recs[0].canonical_status() == "Validated"


def test_parse_accepts_single_hash_heading(tmp_path: Path) -> None:
    p = _board(
        "# H-002: SSRF via fetch-url\n- **Status:** Validated\n",
        tmp_path / "hypotheses.md",
    )
    recs = hypotheses.parse_hypotheses(p)
    assert len(recs) == 1
    assert recs[0].id == "002"


def test_parse_accepts_bare_heading(tmp_path: Path) -> None:
    p = _board(
        "H-003: Stored XSS\n- **Status:** Validated\n",
        tmp_path / "hypotheses.md",
    )
    recs = hypotheses.parse_hypotheses(p)
    assert len(recs) == 1
    assert recs[0].id == "003"


def test_status_normalizes_confidence_suffix(tmp_path: Path) -> None:
    p = _board(
        "### H-004: Mass assignment\n- **Status:** Validated (conf 0.97)\n",
        tmp_path / "hypotheses.md",
    )
    recs = hypotheses.parse_hypotheses(p)
    assert len(recs) == 1
    assert recs[0].status == "Validated"
    assert recs[0].canonical_status() == "Validated"


def test_status_normalizes_descriptive_suffix(tmp_path: Path) -> None:
    p = _board(
        "### H-005: Stored XSS\n- **Status:** Validated (stored raw; render context confirmed)\n",
        tmp_path / "hypotheses.md",
    )
    recs = hypotheses.parse_hypotheses(p)
    assert len(recs) == 1
    assert recs[0].canonical_status() == "Validated"


def test_mixed_heading_depths_all_parse(tmp_path: Path) -> None:
    """A real board mixing ### and ## headings must not drop rows."""
    p = _board(
        "## H-001: IDOR\n- **Status:** Validated\n"
        "### H-002: SSRF\n- **Status:** Validated\n"
        "## H-003: XSS\n- **Status:** Rejected (not reachable)\n",
        tmp_path / "hypotheses.md",
    )
    recs = {r.id: r for r in hypotheses.parse_hypotheses(p)}
    assert set(recs) == {"001", "002", "003"}
    assert recs["003"].canonical_status() == "Rejected"
