"""Regression coverage for release-gate setup in a clean checkout."""

from __future__ import annotations

from pathlib import Path

import yaml

from plugins.violin_guard import schemas, state
from plugins.violin_guard.release import _pytest_basetemp

ROOT = Path(__file__).resolve().parents[3]


def test_profile_does_not_cap_agent_iterations() -> None:
    config = yaml.safe_load((ROOT / "config.yaml").read_text(encoding="utf-8"))

    assert "max_turns" not in config["agent"]


def test_heartbeat_uses_extended_shared_cadence() -> None:
    assert state.COMMAND_INTERVAL == 50
    assert state.MESSAGE_INTERVAL == 60
    description = schemas.HEARTBEAT_DONE_SCHEMA["description"]
    assert "50 target commands or 60 message ticks" in description


def test_pytest_basetemp_creates_missing_engagement_root(tmp_path: Path) -> None:
    engagement_root = tmp_path / "engagements"
    assert not engagement_root.exists()

    basetemp = Path(_pytest_basetemp(tmp_path))

    assert engagement_root.is_dir()
    assert basetemp.is_dir()
    assert basetemp.parent == engagement_root
    assert basetemp.name.startswith(".pytest-release-")
