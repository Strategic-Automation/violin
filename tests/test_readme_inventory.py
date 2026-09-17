"""Guard the inventory counts the README advertises.

The badge row is the first claim a visitor reads, and it drifted once already
when a template was deleted. Count the shipped files the same way and fail the
suite instead of publishing a stale number.
"""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BADGE = re.compile(r"(\d+) playbooks · (\d+) references · (\d+) templates", re.IGNORECASE)


def _shipped(pattern: str) -> int:
    return len(
        [path for path in ROOT.glob(pattern) if path.is_file() and "__pycache__" not in path.parts]
    )


def test_readme_inventory_counts_match_the_repository() -> None:
    match = BADGE.search((ROOT / "README.md").read_text(encoding="utf-8"))

    assert match, "README no longer states the playbook/reference/template inventory"

    advertised = tuple(int(value) for value in match.groups())
    actual = (
        _shipped("skills/*/playbooks/*.md"),
        _shipped("skills/*/references/*"),
        _shipped("skills/*/templates/*"),
    )

    assert advertised == actual, f"README advertises {advertised}, repository ships {actual}"
