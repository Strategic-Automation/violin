"""Review and rebind preserve the same command-phase rules and distinct messages."""

from pathlib import Path

import pytest

from plugins.violin_guard.handlers.ptt_rebind import _validated_replacement_task
from plugins.violin_guard.handlers.ptt_review import _validate_review_ptt_state


@pytest.mark.parametrize("caller", ["review", "rebind"])
@pytest.mark.parametrize(
    "task_phase,pending,error_phases",
    [
        ("RECON", {"commands": [{"phase": "RECON"}]}, ""),
        ("RECON", {"phase": "RECON", "commands": [{}]}, ""),
        ("RECON", {"commands": [{}]}, ""),
        ("RECON", {"phase": "EXPLOITATION", "commands": []}, ""),
        ("EXPLOITATION", {"commands": [{"phase": "POST_EXPLOITATION"}]}, ""),
        ("RECON", {"phase": "EXPLOITATION", "commands": [{}]}, "EXPLOITATION"),
        (
            "RECON",
            {
                "commands": [
                    {"phase": "VULN_RESEARCH"},
                    {"phase": "EXPLOITATION"},
                    {"phase": "EXPLOITATION"},
                ]
            },
            "EXPLOITATION, VULN_RESEARCH",
        ),
    ],
)
def test_pending_phase_decisions(tmp_path: Path, caller, task_phase, pending, error_phases):
    state_dir = tmp_path / "state"
    state_dir.mkdir()
    path = state_dir / "ptt.md"
    path.write_text(
        f"## Phase: {task_phase}\n\n"
        "| ID | Status | Task | Notes |\n"
        "|---|---|---|---|\n"
        "| PT-001 | [~] | Active | |\n"
        "| PT-002 | [x] | Previous | |\n",
        encoding="utf-8",
    )
    before = path.read_bytes()

    def validate():
        if caller == "review":
            return _validate_review_ptt_state(str(tmp_path), "PT-001", "[~]", "batch", pending)
        return _validated_replacement_task(str(tmp_path), pending, "PT-002", "PT-001")

    if error_phases:
        with pytest.raises(ValueError) as exc:
            validate()
        label = "batch task" if caller == "review" else "replacement task"
        assert str(exc.value) == f"{label} 'PT-001' is not phase-compatible with {error_phases}"
    else:
        validate()
    assert path.read_bytes() == before


def test_already_recorded_review_preserves_idempotent_phase_bypass(tmp_path):
    state_dir = tmp_path / "state"
    state_dir.mkdir()
    path = state_dir / "ptt.md"
    path.write_text(
        "## Phase: RECON\n\n"
        "| ID | Status | Task | Notes |\n"
        "|---|---|---|---|\n"
        "| PT-001 | [x] | Done | [reviewed-batch:batch] |\n",
        encoding="utf-8",
    )
    _, _, already_recorded = _validate_review_ptt_state(
        str(tmp_path), "PT-001", "[x]", "batch", {"commands": [{"phase": "EXPLOITATION"}]}
    )
    assert already_recorded is True
