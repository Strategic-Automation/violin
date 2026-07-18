"""Regression tests for exact command deduplication."""

from pathlib import Path

from plugins.violin_guard.history import append_history, check_history_staleness, history_contains


def test_history_deduplication_compares_the_recorded_command_field(tmp_path: Path) -> None:
    history = tmp_path / "state" / "history.md"
    history.parent.mkdir()
    for suffix in ("", " | receipt=evidence/executions/test.json"):
        history.write_text(
            f"- 2026-07-14T10:00:00Z | phase=RECON | exit_code=0 | command=echo done{suffix}\n",
            encoding="utf-8",
        )

        errors, _, _ = check_history_staleness(tmp_path, "echo")
        assert not errors

        errors, _, _ = check_history_staleness(tmp_path, "echo done")
        assert errors


def test_written_history_uses_command_length_for_unambiguous_receipt_parsing(
    tmp_path: Path,
) -> None:
    command = "printf 'value | receipt=fake | command_length=1'"
    append_history(tmp_path, command, "RECON", 0, "evidence/executions/test.json")

    errors, _, _ = check_history_staleness(tmp_path, command)
    assert errors
    assert history_contains(tmp_path, command)

    errors, _, infos = check_history_staleness(tmp_path, command, allow_pending_repeat=True)
    assert not errors
    assert any("pending batch" in info for info in infos)


def test_malformed_history_line_does_not_create_a_false_repeat(tmp_path: Path) -> None:
    history = tmp_path / "state" / "history.md"
    history.parent.mkdir()
    history.write_text("previous command: echo done\n", encoding="utf-8")

    errors, _, _ = check_history_staleness(tmp_path, "echo done")
    assert not errors
