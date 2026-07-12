from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
GUARD_ROOT = ROOT

from plugins.violin_guard.core.release import resolve_reference


def test_playbook_reference_paths_resolve_from_pentest_skill_root():
    playbook = GUARD_ROOT / "skills" / "pentest" / "playbooks" / "api-security.md"

    assert resolve_reference(playbook, "references/shared-safety.md") == (
        GUARD_ROOT / "skills" / "pentest" / "references" / "shared-safety.md"
    )
    assert resolve_reference(playbook, "playbooks/recon.md") == (
        GUARD_ROOT / "skills" / "pentest" / "playbooks" / "recon.md"
    )
