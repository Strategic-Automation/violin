"""Engagement paths regression tests."""

from pathlib import Path

from plugins.violin_guard.core.engagement import bootstrap, state
from tests.guard.handlers._burst_helpers import (
    ROOT,
    eng,  # noqa: F401
)


def test_relative_engagement_paths_stay_under_profile_root(monkeypatch):
    monkeypatch.delenv("VIOLIN_ENG_ROOT", raising=False)

    assert state.resolve_eng_dir("engagements/demo") == (ROOT / "engagements" / "demo").resolve()


def test_resolve_eng_dir_cwd_and_init_engagement_artifact_dirs(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "hypotheses.md").write_text("# Hypotheses\n", encoding="utf-8")

    # Empty string resolves to CWD when engagement markers are present
    assert state.resolve_eng_dir("") == tmp_path.resolve()
    # Path("") should behave identically to ""
    assert state.resolve_eng_dir(Path("")) == tmp_path.resolve()

    bootstrap.init_engagement(tmp_path, host="127.0.0.1")
    assert (tmp_path / "evidence" / "executions").is_dir()

    # Relative paths still prefer profile root when neither candidate exists
    monkeypatch.delenv("VIOLIN_ENG_ROOT", raising=False)
    assert state.resolve_eng_dir("engagements/demo") == (ROOT / "engagements" / "demo").resolve()
