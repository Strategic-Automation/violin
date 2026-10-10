"""Foreground admission and burst budgets respect native Hermes deadlines."""

import json
import sys
from types import ModuleType, SimpleNamespace

import pytest

from plugins.violin_guard.gates.command import CheckResult
from plugins.violin_guard.handlers import exec_handlers


@pytest.fixture
def native_deadline(monkeypatch):
    module = ModuleType("agent.deadline")
    values = {"tools.concurrent_batch": 420, "tools.sequential_call": 420}
    module.resolve_timeout = lambda key, **kwargs: values[key]
    monkeypatch.setitem(sys.modules, "agent.deadline", module)
    return values


@pytest.mark.parametrize("count", [3, 20])
def test_short_bursts_keep_default_timeout_and_finish(
    monkeypatch, native_deadline, tmp_path, count
):
    monkeypatch.setattr(exec_handlers, "_check_command_internal", lambda args: CheckResult())
    monkeypatch.setattr(exec_handlers.state, "is_local_bookkeeping_command", lambda command: True)
    captured = []
    monkeypatch.setattr(
        exec_handlers.execution,
        "execute",
        lambda **kwargs: captured.append(kwargs) or {"executed": True, "exit_code": 0},
    )
    result = json.loads(
        exec_handlers.handle_exec_burst({"eng_dir": str(tmp_path), "commands": ["true"] * count})
    )
    assert result["status"] == "batch_complete"
    assert len(captured) == count
    assert all(item["timeout_seconds"] == 180 for item in captured)


def test_burst_clamps_timeout_and_stops_before_next_process(monkeypatch, native_deadline, tmp_path):
    monkeypatch.setattr(exec_handlers, "_check_command_internal", lambda args: CheckResult())
    monkeypatch.setattr(exec_handlers.state, "is_local_bookkeeping_command", lambda command: True)
    ticks = iter([0, 10, 390])
    monkeypatch.setattr(exec_handlers, "time", SimpleNamespace(monotonic=lambda: next(ticks)))
    captured = []
    monkeypatch.setattr(
        exec_handlers.execution,
        "execute",
        lambda **kwargs: captured.append(kwargs) or {"executed": True, "exit_code": 0},
    )
    result = json.loads(
        exec_handlers.handle_exec_burst(
            {"eng_dir": str(tmp_path), "commands": ["true", "true"], "timeout_seconds": 1800}
        )
    )
    assert captured[0]["timeout_seconds"] == 370
    assert len(captured) == 1
    assert result["status"] == "batch_stopped"
    assert result["executed"] == 1
    assert result["skipped"] == 1
    assert result["stopped_after_index"] == 1


def test_foreground_single_rejected_but_background_keeps_tracked_execution(
    monkeypatch, native_deadline, tmp_path
):
    monkeypatch.setattr(exec_handlers, "_check_command_internal", lambda args: CheckResult())
    captured = []
    monkeypatch.setattr(
        exec_handlers.execution,
        "execute",
        lambda **kwargs: (
            captured.append(kwargs)
            or {"status": "running", "executed": True, "execution_id": "tracked"}
        ),
    )
    args = {"command": "true", "eng_dir": str(tmp_path), "phase": "recon", "timeout_seconds": 1800}
    result = json.loads(exec_handlers.handle_exec(args))
    assert result["status"] == "error"
    assert not captured
    result = json.loads(exec_handlers.handle_exec({**args, "background": True}))
    assert result["execution_id"] == "tracked"
    assert captured[0]["background"] is True


def test_native_deadline_configuration_controls_budget(monkeypatch, native_deadline):
    monkeypatch.setattr(exec_handlers, "time", SimpleNamespace(monotonic=lambda: 0))
    native_deadline["tools.concurrent_batch"] = 1000
    assert exec_handlers._foreground_deadline() == 390
    native_deadline["tools.sequential_call"] = 1000
    assert exec_handlers._foreground_deadline() == 970
    native_deadline.update({key: None for key in native_deadline})
    assert exec_handlers._foreground_deadline() is None
