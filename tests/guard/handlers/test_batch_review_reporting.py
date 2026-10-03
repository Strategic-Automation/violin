"""Execution responses expose authoritative pending workflow review."""

import json
from types import SimpleNamespace

import pytest

from plugins.violin_guard.gates.command import CheckResult
from plugins.violin_guard.handlers import exec_handlers, ptt_handlers


@pytest.mark.parametrize("pending", [None, {"batch_id": "pending-batch"}])
@pytest.mark.parametrize("outcome", ["complete", "nonzero", "exception", "deadline"])
def test_burst_reports_pending_review_on_every_terminal_path(
    tmp_path, monkeypatch, pending, outcome
):
    monkeypatch.setattr(exec_handlers, "_check_command_internal", lambda args: CheckResult())
    monkeypatch.setattr(exec_handlers.state, "is_local_bookkeeping_command", lambda command: True)
    monkeypatch.setattr(exec_handlers.state, "get_pending_sync", lambda eng_dir: pending)
    if outcome == "deadline":
        ticks = iter([1, 100])
        monkeypatch.setattr(exec_handlers, "_foreground_deadline", lambda: 100)
        monkeypatch.setattr(exec_handlers, "time", SimpleNamespace(monotonic=lambda: next(ticks)))

    def execute(**kwargs):
        if outcome == "exception":
            raise OSError("execution failed")
        return {"executed": True, "exit_code": 1 if outcome == "nonzero" else 0}

    monkeypatch.setattr(exec_handlers.execution, "execute", execute)
    result = json.loads(
        exec_handlers.handle_exec_burst({"eng_dir": str(tmp_path), "commands": ["first", "second"]})
    )
    assert result["review_required"] is bool(pending)
    assert result["pending_batch_id"] == ("pending-batch" if pending else None)
    assert (
        result["status"]
        == {
            "complete": "batch_complete",
            "nonzero": "batch_stopped",
            "exception": "execution_failed",
            "deadline": "batch_stopped",
        }[outcome]
    )


def test_ptt_pending_denial_identifies_the_batch_without_mutating_state(tmp_path, monkeypatch):
    pending = {"batch_id": "pending-batch", "ptt_task_id": "PT-001"}
    monkeypatch.setattr(ptt_handlers.ptt, "parse_ptt", lambda path: [])
    monkeypatch.setattr(ptt_handlers.state, "get_pending_sync", lambda eng_dir: pending)
    result = json.loads(
        ptt_handlers.handle_record_ptt(
            {
                "eng_dir": str(tmp_path),
                "id": "PT-001",
                "status": "[x]",
                "note": "reviewed",
                "skill": "api-testing",
                "technique": "probe",
            }
        )
    )
    assert result["status"] == "error"
    assert "pending-batch" in result["error"]
    assert "violin_review_batch" in result["error"]
    assert pending == {"batch_id": "pending-batch", "ptt_task_id": "PT-001"}


def test_successful_target_burst_reports_newly_persisted_pending_review(tmp_path, monkeypatch):
    monkeypatch.setattr(exec_handlers, "_check_command_internal", lambda args: CheckResult())
    monkeypatch.setattr(exec_handlers.state, "is_local_bookkeeping_command", lambda command: True)
    assert exec_handlers.state.get_pending_sync(tmp_path) is None

    def execute(**kwargs):
        exec_handlers.state.commit_execution_start(
            tmp_path, "synthetic probe", "RECON", "PT-001", "execution-1"
        )
        return {"executed": True, "exit_code": 0}

    monkeypatch.setattr(exec_handlers.execution, "execute", execute)
    result = json.loads(
        exec_handlers.handle_exec_burst(
            {"eng_dir": str(tmp_path), "phase": "RECON", "commands": ["synthetic probe"]}
        )
    )
    pending = exec_handlers.state.get_pending_sync(tmp_path)
    assert result["status"] == "batch_complete"
    assert result["review_required"] is True
    assert result["pending_batch_id"] == pending["batch_id"]
    assert pending["ptt_reviewed"] is False
