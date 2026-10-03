"""Task parsing must preserve invalid rows for fail-closed validation."""

import pytest

from plugins.violin_guard.core.engagement import ptt


@pytest.mark.parametrize(
    ("status", "title", "error"),
    [("[?]", "Invalid status", "non-standard status"), ("[ ]", "", "empty title")],
)
def test_parse_preserves_invalid_task_rows(tmp_path, status, title, error):
    path = tmp_path / "ptt.md"
    path.write_text(
        "## Phase: RECON\n\n"
        "| ID | Status | Task | Notes |\n"
        "|---|---|---|---|\n"
        "| PT-001 | [~] | Active | |\n"
        f"| PT-002 | {status} | {title} | |\n",
        encoding="utf-8",
    )
    tasks = ptt.parse_ptt(path)
    assert [task.id for task in tasks] == ["PT-001", "PT-002"]
    result = ptt.validate_ptt(tasks)
    assert result.exit_code() != 0
    assert any(error in message for message in result.errors)


@pytest.mark.parametrize("task_phase", ["EXPLOITATION", "POST_EXPLOITATION"])
@pytest.mark.parametrize("requested_phase", ["EXPLOITATION", "POST_EXPLOITATION"])
def test_exploitation_phase_matching_is_symmetric(task_phase, requested_phase):
    task = ptt.PttTask("PT-001", "[~]", "Active", phase=task_phase)
    assert ptt.task_matches_phase(task, requested_phase)
    assert not ptt.task_matches_phase(task, "RECON")
