"""Burst sync credit regression tests."""

import json

from plugins.violin_guard import handlers as service
from plugins.violin_guard.core.engagement import state
from tests.guard.handlers._burst_helpers import (
    _patch_burst,
)
from tests.guard.handlers._burst_helpers import (
    eng as eng,
)


def test_exec_burst_slot_cost_equals_command_count(eng, monkeypatch):
    """A burst costs one slot per non-local command.

    Sized exactly to the phase window it must be admitted: an extra slot of
    hidden cost turns a valid batch into a denial the operator can only discover
    at dispatch, which costs a whole round trip (and the retry tokens).
    """
    rec = _patch_burst(monkeypatch, str(eng))
    limit = state.sync_credit_limit("recon")
    commands = [f"nmap -sV -p {port} 10.10.10.10" for port in range(1, limit + 1)]
    data = json.loads(
        service.handle_exec_burst(
            {
                "eng_dir": str(eng),
                "scope": str(eng / "scope" / "scope.yaml"),
                "phase": "recon",
                "commands": commands,
                "session_id": "ts",
                "skill_loaded_file": str(eng / "state" / ".skill-loaded-ts"),
            }
        )
    )
    assert data["status"] == "batch_complete", data
    assert data["executed"] == limit, data
    assert len(rec["commands"]) == limit, rec["commands"]
    assert state.sync_credit_remaining(eng, "recon") == 0


def test_exec_burst_denial_reports_its_own_slot_accounting(eng, monkeypatch):
    """A denial must explain the slots it computed, not only the shortfall.

    "need 11, have 10" leaves the operator unable to tell a miscount from a
    hidden cost, so the batch is retried unchanged and the window is spent on
    round trips instead of probes.
    """
    _patch_burst(monkeypatch, str(eng))
    commands = [f"nmap -sV -p {port} 10.10.10.10" for port in range(1, 4)]
    state._mutate_runtime(eng, lambda runtime: setattr(runtime.sync, "credit", 1))

    data = json.loads(
        service.handle_exec_burst(
            {
                "eng_dir": str(eng),
                "scope": str(eng / "scope" / "scope.yaml"),
                "phase": "recon",
                "commands": commands,
                "session_id": "ts",
                "skill_loaded_file": str(eng / "state" / ".skill-loaded-ts"),
            }
        )
    )
    assert data["status"] == "denied", data
    reason = data["reason"]
    assert "insufficient sync credit for burst" in reason, reason
    assert f"need {len(commands)}" in reason, reason
    assert f"{len(commands)} command(s)" in reason, reason
    assert "violin_review_batch" in reason, reason
