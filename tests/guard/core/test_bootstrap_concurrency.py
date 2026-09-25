"""Bootstrap must respect workflow and artifact locks without erasing existing state."""

from pathlib import Path

import pytest
from filelock import FileLock, Timeout

from plugins.violin_guard.core.engagement import bootstrap, state


@pytest.mark.parametrize("operation", ["init", "repair"])
def test_bootstrap_waits_for_engagement_workflow(tmp_path, monkeypatch, operation):
    engagement = tmp_path / "engagement"
    assert bootstrap.init_engagement(engagement, host="example.test") == 0
    history = engagement / "state" / "history.md"
    history.unlink()

    def immediate_workflow_lock(eng_dir):
        return FileLock(str(Path(eng_dir) / "state" / "workflow.lock"), timeout=0)

    monkeypatch.setattr(bootstrap, "workflow_lock", immediate_workflow_lock)
    with state.workflow_lock(engagement):
        with pytest.raises(Timeout):
            if operation == "init":
                bootstrap.init_engagement(engagement, host="example.test")
            else:
                bootstrap.check_bootstrap(engagement, auto_repair=True)
        assert not history.exists()


@pytest.mark.parametrize("operation", ["init", "repair", "seed"])
def test_bootstrap_respects_artifact_lock(tmp_path, monkeypatch, operation):
    engagement = tmp_path / "engagement"
    assert bootstrap.init_engagement(engagement, host="example.test") == 0
    target = (
        engagement / "state" / ("coverage-matrix.yaml" if operation == "seed" else "history.md")
    )
    original = target.read_text(encoding="utf-8")
    if operation != "seed":
        target.unlink()

    def immediate_file_lock(path):
        return FileLock(str(path.with_suffix(path.suffix + ".lock")), timeout=0)

    monkeypatch.setattr(bootstrap, "lock_file", immediate_file_lock)
    with state.lock_file(target):
        if operation == "repair":
            result = bootstrap.check_bootstrap(engagement, auto_repair=True)
            assert any("AUTO-REPAIR FAILED" in error for error in result.errors)
        else:
            with pytest.raises(Timeout):
                if operation == "init":
                    bootstrap.init_engagement(engagement, host="example.test")
                else:
                    bootstrap._seed_coverage_matrix(
                        engagement, {"engagement": {"coverage_obligations": ["http"]}}
                    )
        if operation == "seed":
            assert target.read_text(encoding="utf-8") == original
        else:
            assert not target.exists()


def test_artifact_creation_rechecks_existing_state(tmp_path):
    target = tmp_path / "state" / "history.md"
    target.parent.mkdir()
    target.write_text("Existing command history\n", encoding="utf-8")

    bootstrap._create_artifact(tmp_path, Path("state/history.md"), None, "placeholder\n")

    assert target.read_text(encoding="utf-8") == "Existing command history\n"
