"""Regression coverage for release-gate setup in a clean checkout."""

from __future__ import annotations

import re
import tomllib
from pathlib import Path

import yaml

from plugins.violin_guard import release, schemas, state
from plugins.violin_guard.engine.release import ReleaseCheckResult, _pytest_basetemp

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


def test_all_release_version_surfaces_match_exact_semver() -> None:
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    distribution = yaml.safe_load((ROOT / "distribution.yaml").read_text(encoding="utf-8"))
    plugin = yaml.safe_load(
        (ROOT / "plugins" / "violin_guard" / "plugin.yaml").read_text(encoding="utf-8")
    )
    changelog = re.search(
        r"(?m)^## (\d+\.\d+\.\d+)(?: \(Unreleased\))?$",
        (ROOT / "CHANGELOG.md").read_text(encoding="utf-8"),
    )
    versions = {
        project["project"]["version"],
        str(distribution["version"]),
        str(plugin["version"]),
        changelog.group(1) if changelog else "",
    }
    assert versions == {"3.2.0"}
    assert any(
        str(dependency).lower().startswith("pyyaml")
        for dependency in project["project"]["dependencies"]
    )


def test_release_main_exits_nonzero_only_for_errors(monkeypatch) -> None:
    warning = ReleaseCheckResult(warnings=["review"])
    monkeypatch.setattr(release, "check_release", lambda: warning)
    assert release.main() == 0

    failure = ReleaseCheckResult(errors=["broken"])
    monkeypatch.setattr(release, "check_release", lambda: failure)
    assert release.main() == 1
