"""Accounting failures cannot erase the fact that a command launched."""

import json
import sys

from plugins.violin_guard.core.engagement import state
from plugins.violin_guard.core.results import GuardResult
from plugins.violin_guard.engine import execution, execution_lifecycle
from plugins.violin_guard.handlers import exec_handlers


def test_double_accounting_failure_finalizes_and_recovers_truthfully(tmp_path, monkeypatch):
    (tmp_path / "state").mkdir()
    (tmp_path / "state/history.md").write_text("# History\n", encoding="utf-8")
    (tmp_path / "state/ptt.md").write_text(
        "## Phase: RECON\n\n| ID | Status | Task | Notes |\n|---|---|---|---|\n"
        "| PT-001 | [~] | Probe | active |\n",
        encoding="utf-8",
    )
    calls = []
    original = state.commit_execution_start

    def fail_accounting(*args, **kwargs):
        calls.append(args)
        raise OSError("accounting write unavailable")

    monkeypatch.setattr(state, "commit_execution_start", fail_accounting)
    monkeypatch.setattr(exec_handlers, "_check_command_internal", lambda args: GuardResult())
    response = json.loads(
        exec_handlers.handle_exec(
            {"eng_dir": str(tmp_path), "phase": "recon", "command": "guarded probe"},
            _internal_argv=[sys.executable, "-c", "import time; time.sleep(5)"],
        )
    )
    assert len(calls) == 2
    assert response["status"] == "execution_failed"
    assert response["executed"] is True
    assert response["execution_status"] == "failed_to_track"
    assert response["accounting_pending"] is True
    assert response["sync_required"] is True
    assert response["history_recorded"] is True
    manifest = tmp_path / response["evidence_paths"]["manifest"]
    assert json.loads(manifest.read_text(encoding="utf-8"))["status"] == "failed_to_track"
    assert execution.status(str(tmp_path), response["execution_id"])["accounting_pending"]

    monkeypatch.setattr(state, "commit_execution_start", original)
    recovered = execution.status(str(tmp_path), response["execution_id"])
    assert recovered["accounting_pending"] is False
    assert "accounting_error" not in recovered
    assert state.read_counts(tmp_path)["commands"] == 1

    execution.status(str(tmp_path), response["execution_id"])
    assert state.read_counts(tmp_path)["commands"] == 1


def test_history_failure_reports_execution_and_preserves_terminal_intent(tmp_path, monkeypatch):
    (tmp_path / "state").mkdir()
    (tmp_path / "state/ptt.md").write_text(
        "## Phase: RECON\n\n| ID | Status | Task | Notes |\n|---|---|---|---|\n"
        "| PT-001 | [~] | Probe | active |\n",
        encoding="utf-8",
    )
    original = execution_lifecycle.append_history

    def fail_history(*args, **kwargs):
        raise OSError("history write unavailable")

    monkeypatch.setattr(execution_lifecycle, "append_history", fail_history)
    monkeypatch.setattr(exec_handlers, "_check_command_internal", lambda args: GuardResult())
    response = json.loads(
        exec_handlers.handle_exec(
            {"eng_dir": str(tmp_path), "phase": "recon", "command": "guarded probe"},
            _internal_argv=[sys.executable, "-c", "print('done')"],
        )
    )
    assert response["status"] == "execution_failed"
    assert response["executed"] is True
    assert response["execution_status"] == "failed_to_finalize"
    manifest = tmp_path / response["evidence_paths"]["manifest"]
    stored = json.loads(manifest.read_text(encoding="utf-8"))
    assert stored["status"] == "finalizing"
    assert stored["terminal"]["status"] == "completed"
    assert stored["terminal"]["exit_code"] == 0
    monkeypatch.setattr(execution_lifecycle, "append_history", original)
    recovered = execution.status(str(tmp_path), response["execution_id"])
    assert recovered["status"] == "completed"
    assert recovered["history_recorded"] is True
    execution.status(str(tmp_path), response["execution_id"])
    assert state.read_counts(tmp_path)["commands"] == 1
