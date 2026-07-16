"""Regression tests for exact command deduplication."""

from pathlib import Path

from plugins.violin_guard.core.command import check_history_staleness


def test_history_deduplication_compares_the_recorded_command_field(tmp_path: Path) -> None:
    history = tmp_path / "state" / "history.md"
    history.parent.mkdir()
    history.write_text(
        "- 2026-07-14T10:00:00Z | phase=RECON | exit_code=0 | command=echo done\n",
        encoding="utf-8",
    )

    assert not check_history_staleness(tmp_path, "echo").errors
    assert check_history_staleness(tmp_path, "echo done").errors


def test_malformed_history_line_does_not_create_a_false_repeat(tmp_path: Path) -> None:
    history = tmp_path / "state" / "history.md"
    history.parent.mkdir()
    history.write_text("previous command: echo done\n", encoding="utf-8")

    assert not check_history_staleness(tmp_path, "echo done").errors
