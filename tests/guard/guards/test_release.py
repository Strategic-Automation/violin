"""Regression coverage for release-gate setup in a clean checkout."""

from __future__ import annotations

from pathlib import Path

import yaml

from plugins.violin_guard import schemas, state
from plugins.violin_guard.release import _pytest_basetemp

ROOT = Path(__file__).resolve().parents[3]


def test_profile_uses_an_engagement_sized_iteration_budget() -> None:
    config = yaml.safe_load((ROOT / "config.yaml").read_text(encoding="utf-8"))

    assert config["agent"]["max_turns"] >= 350


def test_heartbeat_is_command_based_and_phase_aware() -> None:
    assert state.COMMAND_INTERVAL == 50
    description = schemas.HEARTBEAT_DONE_SCHEMA["description"]
    assert "50 executed target commands" in description
    assert "message ticks" not in description


def test_pytest_basetemp_creates_missing_engagement_root(tmp_path: Path) -> None:
    engagement_root = tmp_path / "engagements"
    assert not engagement_root.exists()

    basetemp = Path(_pytest_basetemp(tmp_path))

    assert engagement_root.is_dir()
    assert basetemp.is_dir()
    assert basetemp.parent == engagement_root
    assert basetemp.name.startswith(".pytest-release-")
