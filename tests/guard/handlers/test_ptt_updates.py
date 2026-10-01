from __future__ import annotations

import concurrent.futures
from pathlib import Path

import pytest

from plugins.violin_guard.core.engagement import bootstrap, ptt, state
from plugins.violin_guard.handlers.ptt_gates import (
    _redact_sensitive_note,
)
from plugins.violin_guard.handlers.ptt_handlers import _start_ptt_task


def test_multi_task_ptt_update_validates_before_atomic_replace(tmp_path: Path) -> None:
    path = tmp_path / "ptt.md"
    path.write_text(
        "## Phase: RECON\n\n"
        "| ID | Status | Task | Notes |\n"
        "|---|---|---|---|\n"
        "| PT-001 | [~] | Active | original |\n"
        "| PT-002 | [ ] | Next | untouched |\n",
        encoding="utf-8",
    )
    original = path.read_text(encoding="utf-8")
    with pytest.raises(ValueError, match="PT-999"):
        ptt.update_tasks(path, {"PT-001": ("[x]", "done"), "PT-999": ("[~]", "bad")})
    assert path.read_text(encoding="utf-8") == original


def test_concurrent_ptt_transitions_are_serialized_by_workflow_lock(tmp_path: Path) -> None:
    engagement = tmp_path / "engagement"
    assert bootstrap.init_engagement(engagement, host="10.10.10.10") == 0
    ptt_path = engagement / "state" / "ptt.md"

    def start(task_id: str) -> None:
        with state.workflow_lock(engagement):
            tasks = ptt.parse_ptt(ptt_path)
            _start_ptt_task(
                ptt_path,
                tasks,
                task_id,
                "[~]",
                f"started {task_id}",
                eng_dir=engagement,
            )

    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        list(pool.map(start, ("PT-010", "PT-011")))

    tasks = ptt.parse_ptt(ptt_path)
    assert len([task for task in tasks if task.status == "[~]"]) == 1
    assert {task.id for task in tasks} >= {"PT-010", "PT-011"}


def test_ptt_notes_redact_credentials_before_persisting() -> None:
    note = (
        "JWT eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.signature "
        "Authorization: Bearer bearer-secret "
        "key sk-or-v1-abcdefghijklmnopqrstuvwxyz0123456789"
    )
    redacted = _redact_sensitive_note(note)
    assert "eyJhbGciOiJIUzI1NiJ9" not in redacted
    assert "bearer-secret" not in redacted
    assert "sk-or-v1-abcdefghijklmnopqrstuvwxyz0123456789" not in redacted
    assert "[REDACTED_JWT]" in redacted
    assert "Bearer [REDACTED_TOKEN]" in redacted
    assert "[REDACTED_API_KEY]" in redacted
