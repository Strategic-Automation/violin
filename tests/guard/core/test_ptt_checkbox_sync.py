"""Unit tests verifying PTT top summary checklist synchronization and sync_ptt helper."""

from pathlib import Path

import pytest

from plugins.violin_guard.core import ptt


def test_sync_ptt_top_checkboxes(tmp_path: Path):
    ptt_file = tmp_path / "ptt.md"
    content = (
        "# Pentesting Task Tree (PTT)\n"
        "- [ ] PT-101 Reconnaissance & Tech Detection\n"
        "- [ ] PT-102 Vulnerability Assessment\n"
        "- [ ] PT-103 Exploitation & Closeout\n\n"
        "## Phase: RECON\n\n"
        "| ID | Status | Task | Notes |\n"
        "|---|---|---|---|\n"
        "| PT-101 | [x] | PT-101 | Recon complete |\n\n"
        "## Phase: REPORTING\n\n"
        "| ID | Status | Task | Notes |\n"
        "|---|---|---|---|\n"
        "| PT-102 | [x] | PT-102 | Report generated |\n"
        "| PT-103 | [x] | PT-103 | Closeout complete |\n"
    )
    ptt_file.write_text(content, encoding="utf-8")

    # Run sync_ptt
    ptt.sync_ptt(ptt_file)

    synced_content = ptt_file.read_text(encoding="utf-8")
    assert "- [x] PT-101 Reconnaissance & Tech Detection" in synced_content
    assert "- [x] PT-102 Vulnerability Assessment" in synced_content
    assert "- [x] PT-103 Exploitation & Closeout" in synced_content


def test_update_task_auto_syncs_top_checkboxes(tmp_path: Path):
    ptt_file = tmp_path / "ptt.md"
    content = (
        "# Pentesting Task Tree (PTT)\n"
        "- [ ] PT-101 Reconnaissance\n"
        "- [ ] PT-102 Reporting\n\n"
        "## Phase: RECON\n\n"
        "| ID | Status | Task | Notes |\n"
        "|---|---|---|---|\n"
        "| PT-101 | [ ] | PT-101 | Initial |\n\n"
        "## Phase: REPORTING\n\n"
        "| ID | Status | Task | Notes |\n"
        "|---|---|---|---|\n"
        "| PT-102 | [ ] | PT-102 | Initial |\n"
    )
    ptt_file.write_text(content, encoding="utf-8")

    # Update PT-101 to [x]
    ptt.update_task(ptt_file, "PT-101", "[x]", "Recon finished")

    synced = ptt_file.read_text(encoding="utf-8")
    assert "- [x] PT-101 Reconnaissance" in synced
    assert "- [ ] PT-102 Reporting" in synced


def test_parse_ignores_fenced_and_non_task_tables(tmp_path: Path) -> None:
    path = tmp_path / "ptt.md"
    path.write_text(
        "# PTT\n\n"
        "## Notes\n\n"
        "| ID | Status | Task | Notes |\n|---|---|---|---|\n"
        "| PT-900 | [ ] | outside a phase | example |\n\n"
        "## Phase: RECON\n\n"
        "```markdown\n"
        "| ID | Status | Task | Notes |\n|---|---|---|---|\n"
        "| PT-901 | [ ] | fenced example | ignore |\n````\n\n"
        "| Column | Description |\n|---|---|\n| PT-902 | prose table |\n\n"
        "| ID | Status | Task | Notes |\n|---|---|---|---|\n"
        "| PT-001 | [ ] | real row | evidence |\n",
        encoding="utf-8",
    )

    assert [(task.id, task.phase) for task in ptt.parse_ptt(path)] == [("PT-001", "RECON")]


def test_update_preserves_crlf_and_unowned_table_source(tmp_path: Path) -> None:
    path = tmp_path / "ptt.md"
    original = (
        "# PTT\r\n\r\n"
        "## Phase: RECON\r\n\r\n"
        "| ID | Status | Task | Notes |\r\n"
        "|---|---|---|---|\r\n"
        "| PT-001 | [ ] | Real task | evidence |\r\n\r\n"
        "## Notes\r\n\r\n"
        "| ID | Status | Task | Notes |\r\n|---|---|---|---|\r\n"
        "| PT-999 | [ ] | Example only | preserve |\r\n"
    )
    path.write_bytes(original.encode("utf-8"))

    ptt.update_task(path, "PT-001", "[x]", "finished")

    updated = path.read_bytes().decode("utf-8")
    assert "| PT-001 | [x] | Real task | finished |\r\n" in updated
    assert "| PT-999 | [ ] | Example only | preserve |\r\n" in updated
    assert "\n" not in updated.replace("\r\n", "")


@pytest.mark.parametrize("note", ["stored <img onerror>", "DOM link <a href={o}>", "JS a || b"])
def test_task_notes_round_trip_without_disappearing(tmp_path: Path, note: str) -> None:
    path = tmp_path / "ptt.md"
    path.write_text(
        "# PTT\n\n## Phase: RECON\n\n"
        "| ID | Status | Task | Notes |\n|---|---|---|---|\n"
        "| PT-101 | [~] | Recon | initial |\n",
        encoding="utf-8",
    )

    updated = ptt.update_task(path, "PT-101", "[x]", note)

    assert updated.id == "PT-101"
    assert updated.status == "[x]"
    assert updated.note == note
    assert [(task.id, task.note) for task in ptt.parse_ptt(path)] == [("PT-101", note)]


def test_invalid_multiline_note_cannot_partially_update_ptt(tmp_path: Path) -> None:
    path = tmp_path / "ptt.md"
    original = (
        "# PTT\n\n## Phase: RECON\n\n"
        "| ID | Status | Task | Notes |\n|---|---|---|---|\n"
        "| PT-101 | [~] | Recon | initial |\n"
    )
    path.write_text(original, encoding="utf-8")

    with pytest.raises(ValueError, match="single-line"):
        ptt.update_task(path, "PT-101", "[x]", "line one\nline two")

    assert path.read_text(encoding="utf-8") == original
