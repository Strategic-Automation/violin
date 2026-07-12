import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

from guard.core import ROOT as GUARD_ROOT  # noqa: E402
from guard.release import resolve_reference  # noqa: E402


def test_playbook_reference_paths_resolve_from_pentest_skill_root():
    playbook = GUARD_ROOT / "skills" / "pentest" / "playbooks" / "api-security.md"

    assert resolve_reference(playbook, "references/shared-safety.md") == (
        GUARD_ROOT / "skills" / "pentest" / "references" / "shared-safety.md"
    )
    assert resolve_reference(playbook, "playbooks/recon.md") == (
        GUARD_ROOT / "skills" / "pentest" / "playbooks" / "recon.md"
    )
