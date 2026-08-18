"""Prevent playbook filenames from shadowing their parent skill names."""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]


def test_playbook_names_do_not_shadow_parent_skills() -> None:
    for skill_file in (ROOT / "skills").glob("*/SKILL.md"):
        skill_name = skill_file.parent.name
        collisions = [
            playbook
            for playbook in (skill_file.parent / "playbooks").glob("*.md")
            if playbook.stem == skill_name
        ]
        assert not collisions, (
            "Hermes legacy skill lookup treats <skill-name>.md as a candidate; "
            f"rename these playbooks to avoid a collision with {skill_name!r}: {collisions}"
        )
