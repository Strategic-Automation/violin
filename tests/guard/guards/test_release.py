"""Regression coverage for release-gate setup in a clean checkout."""

from __future__ import annotations

from pathlib import Path

from plugins.violin_guard.release import _pytest_basetemp


def test_pytest_basetemp_creates_missing_engagement_root(tmp_path: Path) -> None:
    engagement_root = tmp_path / "engagements"
    assert not engagement_root.exists()

    basetemp = Path(_pytest_basetemp(tmp_path))

    assert engagement_root.is_dir()
    assert basetemp.is_dir()
    assert basetemp.parent == engagement_root
    assert basetemp.name.startswith(".pytest-release-")
