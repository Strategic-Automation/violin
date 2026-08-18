"""Tests for automatic guard-friction logging (framework feedback as it happens)."""

from __future__ import annotations

from pathlib import Path

from plugins.violin_guard.gates.command import CheckResult
from plugins.violin_guard.handlers.base import _log_guard_friction


def _feedback_file(eng_dir: Path) -> Path:
    return eng_dir / "state" / "framework_feedback.md"


def test_log_guard_friction_appends_block_row(tmp_path: Path) -> None:
    eng_dir = tmp_path / "eng"
    (eng_dir / "state").mkdir(parents=True)
    feedback = _feedback_file(eng_dir)
    feedback.write_text(
        "# Violin Framework Feedback & Friction Log\n\n| Timestamp | Category | Issue | Impact | Prevention |\n|---|---|---|---|---|\n",
        encoding="utf-8",
    )
    result = CheckResult()
    result.add_error("destructive filesystem deletion (rm -rf) is blocked")
    _log_guard_friction(eng_dir, result, "rm -rf /")
    text = feedback.read_text(encoding="utf-8")
    assert "Guard Block" in text
    assert "rm -rf" in text
    assert "destructive filesystem deletion" in text
    assert "use violin_record_hypothesis / violin_record_ptt / violin_exec" in text


def test_log_guard_friction_noop_without_file(tmp_path: Path) -> None:
    """Non-benchmark engagements (no framework_feedback.md) are untouched."""
    eng_dir = tmp_path / "eng"
    (eng_dir / "state").mkdir(parents=True)
    result = CheckResult()
    result.add_error("some block")
    _log_guard_friction(eng_dir, result, "cmd")
    assert not _feedback_file(eng_dir).exists()


def test_log_guard_friction_noop_without_errors(tmp_path: Path) -> None:
    eng_dir = tmp_path / "eng"
    (eng_dir / "state").mkdir(parents=True)
    feedback = _feedback_file(eng_dir)
    feedback.write_text("header\n", encoding="utf-8")
    result = CheckResult()
    result.add_info("all good")
    _log_guard_friction(eng_dir, result, "ok-cmd")
    assert "Guard" not in feedback.read_text(encoding="utf-8")


def test_log_guard_friction_dedupes_identical_rows(tmp_path: Path) -> None:
    eng_dir = tmp_path / "eng"
    (eng_dir / "state").mkdir(parents=True)
    feedback = _feedback_file(eng_dir)
    feedback.write_text(
        "| Timestamp | Category | Issue | Impact | Prevention |\n|---|---|---|---|---|\n",
        encoding="utf-8",
    )
    result = CheckResult()
    result.add_error("same issue twice")
    _log_guard_friction(eng_dir, result, "cmd")
    _log_guard_friction(eng_dir, result, "cmd")
    assert feedback.read_text(encoding="utf-8").count("same issue twice") == 1


def test_log_guard_friction_escapes_pipes(tmp_path: Path) -> None:
    eng_dir = tmp_path / "eng"
    (eng_dir / "state").mkdir(parents=True)
    feedback = _feedback_file(eng_dir)
    feedback.write_text("header\n", encoding="utf-8")
    result = CheckResult()
    result.add_error("a | b | c")
    _log_guard_friction(eng_dir, result, "cmd")
    text = feedback.read_text(encoding="utf-8")
    # the pipe inside the issue must not split the table row into extra cells
    assert text.count("| a \\| b \\| c |") == 1
