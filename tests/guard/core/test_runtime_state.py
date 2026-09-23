"""Versioned executor-state contract and fail-closed regressions."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from plugins.violin_guard.core.engagement import state
from plugins.violin_guard.core.runtime_state import RuntimeStateError


def test_legacy_engagement_state_requires_reinitialization(tmp_path: Path) -> None:
    engagement_state = tmp_path / "engagement" / "state"
    engagement_state.mkdir(parents=True)
    legacy_sync = engagement_state / "sync.json"
    legacy_sync.write_text(
        json.dumps({"credit": 6, "pending": {"batch_id": "batch-1"}}), encoding="utf-8"
    )

    with pytest.raises(
        RuntimeStateError, match="reinitialize the engagement or start a new engagement"
    ):
        state.sync_credit_remaining(tmp_path / "engagement", "RECON")
    assert not (engagement_state / "runtime.json").exists()
    assert legacy_sync.exists()


def test_legacy_counts_or_heartbeat_alone_also_require_reinitialization(tmp_path: Path) -> None:
    engagement_state = tmp_path / "engagement" / "state"
    engagement_state.mkdir(parents=True)
    (engagement_state / "counts.json").write_text('{"commands": 0}', encoding="utf-8")

    with pytest.raises(RuntimeStateError, match="Violin 3.3 state"):
        state.read_counts(tmp_path / "engagement")
    assert not (engagement_state / "runtime.json").exists()


def test_fresh_engagement_gets_combined_defaults_on_first_write(tmp_path: Path) -> None:
    engagement = tmp_path / "engagement"
    assert state.sync_credit_remaining(engagement, "RECON") == 10
    assert state.read_counts(engagement) == {"commands": 0, "messages": 0}
    assert not state.has_heartbeat_pending(engagement)
    assert not (engagement / "state" / "runtime.json").exists()

    state.tick_command(engagement)
    persisted = json.loads((engagement / "state" / "runtime.json").read_text(encoding="utf-8"))
    assert persisted == {
        "schema_version": 1,
        "sync": {
            "credit": None,
            "reservations": {},
            "pending": None,
            "rebind_audit": [],
            "execution_accounts": {},
        },
        "counts": {"commands": 1, "messages": 0, "last_check": None, "execution_ids": []},
        "heartbeat": {"pending": False, "reason": None, "created_at": None},
    }


def test_unknown_runtime_schema_fails_closed(tmp_path: Path) -> None:
    engagement_state = tmp_path / "engagement" / "state"
    engagement_state.mkdir(parents=True)
    (engagement_state / "runtime.json").write_text(
        json.dumps({"schema_version": 2, "sync": {"credit": 10}}), encoding="utf-8"
    )

    with pytest.raises(RuntimeStateError, match="malformed or unsupported"):
        state.sync_credit_remaining(tmp_path / "engagement", "RECON")


def test_runtime_write_failure_keeps_the_previous_complete_state(
    tmp_path: Path, monkeypatch
) -> None:
    engagement = tmp_path / "engagement"
    state.tick_command(engagement)
    runtime_path = engagement / "state" / "runtime.json"
    before = runtime_path.read_text(encoding="utf-8")

    def fail_write(*args, **kwargs):
        raise OSError("simulated replace failure")

    monkeypatch.setattr(state, "atomic_json", fail_write)
    with pytest.raises(OSError, match="simulated replace failure"):
        state.set_heartbeat_pending(engagement, "review cadence")
    assert runtime_path.read_text(encoding="utf-8") == before
    assert not state.has_heartbeat_pending(engagement)


def test_legacy_state_blocks_even_if_runtime_file_exists(tmp_path: Path) -> None:
    engagement_state = tmp_path / "engagement" / "state"
    engagement_state.mkdir(parents=True)
    (engagement_state / "runtime.json").write_text(
        json.dumps({"schema_version": 1}), encoding="utf-8"
    )
    (engagement_state / "heartbeat.json").write_text(
        json.dumps({"pending": True}), encoding="utf-8"
    )

    with pytest.raises(RuntimeStateError, match="reinitialize the engagement"):
        state.has_heartbeat_pending(tmp_path / "engagement")
