"""Unit tests verifying PTT top summary checklist synchronization and sync_ptt helper."""

from pathlib import Path

from plugins.violin_guard import ptt


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
