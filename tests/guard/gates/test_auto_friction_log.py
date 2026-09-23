"""Tests for automatic guard-friction logging (feedback recorded as it happens).

Guard rows are written to state/guard_feedback.md — their own file under their
own heading — so a guard-side write never invalidates an agent edit queued
against the agent-maintained state/framework_feedback.md table.
"""

from __future__ import annotations

from pathlib import Path

from plugins.violin_guard.gates.command import CheckResult
from plugins.violin_guard.handlers.base import _log_guard_friction


def _feedback_file(eng_dir: Path) -> Path:
    return eng_dir / "state" / "guard_feedback.md"


def test_log_guard_friction_appends_block_row(tmp_path: Path) -> None:
    eng_dir = tmp_path / "eng"
    (eng_dir / "state").mkdir(parents=True)
    # Feedback-enabled engagement: framework_feedback.md marks it as opted in.
    (eng_dir / "state" / "framework_feedback.md").write_text("header\n", encoding="utf-8")
    result = CheckResult()
    result.add_error("destructive filesystem deletion (rm -rf) is blocked")
    _log_guard_friction(eng_dir, result, "rm -rf /")
    text = _feedback_file(eng_dir).read_text(encoding="utf-8")
    assert "Guard Block" in text
    assert "rm -rf" in text
    assert "destructive filesystem deletion" in text
    assert "use violin_record_hypothesis / violin_record_ptt / violin_exec" in text
    # The agent-maintained table is left untouched by the guard write.
    assert (eng_dir / "state" / "framework_feedback.md").read_text(encoding="utf-8") == "header\n"


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
    (eng_dir / "state" / "framework_feedback.md").write_text("header\n", encoding="utf-8")
    result = CheckResult()
    result.add_info("all good")
    _log_guard_friction(eng_dir, result, "ok-cmd")
    assert not _feedback_file(eng_dir).exists()


def test_log_guard_friction_dedupes_identical_rows(tmp_path: Path) -> None:
    eng_dir = tmp_path / "eng"
    (eng_dir / "state").mkdir(parents=True)
    (eng_dir / "state" / "framework_feedback.md").write_text("header\n", encoding="utf-8")
    result = CheckResult()
    result.add_error("same issue twice")
    _log_guard_friction(eng_dir, result, "cmd")
    _log_guard_friction(eng_dir, result, "cmd")
    assert _feedback_file(eng_dir).read_text(encoding="utf-8").count("same issue twice") == 1


def test_log_guard_friction_escapes_pipes(tmp_path: Path) -> None:
    eng_dir = tmp_path / "eng"
    (eng_dir / "state").mkdir(parents=True)
    (eng_dir / "state" / "framework_feedback.md").write_text("header\n", encoding="utf-8")
    result = CheckResult()
    result.add_error("a | b | c")
    _log_guard_friction(eng_dir, result, "cmd")
    text = _feedback_file(eng_dir).read_text(encoding="utf-8")
    # the pipe inside the issue must not split the table row into extra cells
    assert text.count("| a \\| b \\| c |") == 1


def test_log_guard_friction_noop_on_advisory_hints(tmp_path: Path) -> None:
    """Advisory hints (exit code 0) must not write guard feedback."""
    eng_dir = tmp_path / "eng"
    (eng_dir / "state").mkdir(parents=True)
    (eng_dir / "state" / "framework_feedback.md").write_text("header\n", encoding="utf-8")
    result = CheckResult()
    result.add_hint("hint: hypothesis H-001 predates evidence. This is a hint, not a block.")
    _log_guard_friction(eng_dir, result, "curl http://10.0.0.1")
    assert not _feedback_file(eng_dir).exists()


def test_guard_row_does_not_invalidate_queued_agent_edit(tmp_path: Path) -> None:
    """A guard block during a pending agent edit must not invalidate the edit.

    The agent maintains state/framework_feedback.md through its patch tool and
    snapshots it before queuing an edit. If the guard appended into that same
    file, the file would change underneath the queued edit and the patch would
    fail ('file was modified since you last read'). Guard rows therefore go to
    a separate file (state/guard_feedback.md), leaving the frame the agent
    edits byte-for-byte untouched.
    """
    eng_dir = tmp_path / "eng"
    (eng_dir / "state").mkdir(parents=True)
    feedback = eng_dir / "state" / "framework_feedback.md"
    agent_view = (
        "# Violin Framework Feedback & Friction Log\n"
        "\n"
        "| Timestamp | Category | Issue Description | Impact / Workaround | "
        "Prevention Suggestion |\n"
        "|---|---|---|---|---|\n"
    )
    feedback.write_text(agent_view, encoding="utf-8")

    # The agent reads the file and queues an edit against that exact snapshot.
    queued_old = "Prevention Suggestion |"
    queued_new = "Prevention Suggestion |\n| 2026-01-01 UTC | Guard Code Inspection | read scope | n/a | clearer errors |"

    # A guard block fires mid-edit and appends its friction row.
    result = CheckResult()
    result.add_error("destructive filesystem deletion (rm -rf) is blocked")
    _log_guard_friction(eng_dir, result, "rm -rf /")
    guard_text = _feedback_file(eng_dir).read_text(encoding="utf-8")
    assert "Guard Block" in guard_text
    # The guard file carries its own heading/schema, distinct from the
    # agent-facing table (distinguishable without reading any date column).
    assert "| Timestamp | Category | Issue | Impact | Prevention |" in guard_text

    # The agent's patch anchor still resolves because the file it edits is
    # byte-for-byte what it read — the guard wrote elsewhere.
    assert feedback.read_text(encoding="utf-8") == agent_view
    applied = feedback.read_text(encoding="utf-8").replace(queued_old, queued_new)
    assert "Guard Code Inspection" in applied
    assert "Guard Block" not in applied  # guard rows never leak into the agent table
