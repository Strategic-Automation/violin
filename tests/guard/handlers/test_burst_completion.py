"""Burst results distinguish policy stops from complete attempts."""

import json

import pytest

from plugins.violin_guard.gates.command import CheckResult
from plugins.violin_guard.handlers import exec_handlers


@pytest.mark.parametrize("continue_on_error", [False, True])
@pytest.mark.parametrize("failure", ["nonzero", "exception", "finalization"])
def test_burst_reports_unattempted_commands(tmp_path, monkeypatch, continue_on_error, failure):
    launched = []
    released = []
    monkeypatch.setattr(exec_handlers, "_check_command_internal", lambda args: CheckResult())
    monkeypatch.setattr(exec_handlers.state, "is_local_bookkeeping_command", lambda command: False)
    monkeypatch.setattr(exec_handlers.state, "reserve_sync_credit", lambda *args: "reservation")
    monkeypatch.setattr(
        exec_handlers.state, "release_reserved_sync_credit", lambda *args: released.append(args)
    )

    def execute(**kwargs):
        launched.append(kwargs["command"])
        if len(launched) == 1:
            if failure == "exception":
                raise OSError("process did not start")
            if failure == "finalization":
                return {
                    "status": "failed_to_finalize",
                    "executed": True,
                    "exit_code": None,
                    "finalization_error": "history unavailable",
                }
            return {"status": "completed", "executed": True, "exit_code": 23}
        return {"status": "completed", "executed": True, "exit_code": 0}

    monkeypatch.setattr(exec_handlers.execution, "execute", execute)
    commands = ["first", "second", "third"]
    data = json.loads(
        exec_handlers.handle_exec_burst(
            {
                "eng_dir": str(tmp_path),
                "phase": "recon",
                "commands": commands,
                "continue_on_error": continue_on_error,
            }
        )
    )

    assert len(released) == 1
    if continue_on_error:
        assert launched == commands
        assert data["status"] == "batch_complete"
        assert len(data["results"]) == 3
        assert "skipped" not in data
        assert data["executed"] == (2 if failure == "exception" else 3)
    else:
        assert launched == commands[:1]
        assert data["status"] == ("execution_failed" if failure == "exception" else "batch_stopped")
        assert data["stopped_after_index"] == 1
        assert data["skipped"] == 2
        assert len(data["results"]) == 1
        assert data["executed"] == (0 if failure == "exception" else 1)
        if failure == "finalization":
            assert data["results"][0]["executed"] is True
            assert data["results"][0]["finalization_error"] == "history unavailable"
