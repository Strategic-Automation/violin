"""Pending-sync batches must stay bound to their original PTT task."""

from __future__ import annotations

import json
from pathlib import Path

from plugins.violin_guard.core import bootstrap, service, state


def _engagement(tmp_path: Path) -> Path:
    eng = tmp_path / "10.10.10.10-2026-07-13"
    assert bootstrap.init_engagement(eng, host="10.10.10.10") == 0
    ptt_path = eng / "state" / "ptt.md"
    ptt_path.write_text(
        ptt_path.read_text(encoding="utf-8").replace("| PT-010 | [ ] |", "| PT-010 | [~] |"),
        encoding="utf-8",
    )
    return eng


def test_review_cannot_switch_the_batch_to_a_new_active_task(tmp_path: Path) -> None:
    eng = _engagement(tmp_path)
    command = "nmap -p 80 10.10.10.10"
    state.append_history(eng, command, "RECON", 0, "evidence/executions/test.json")
    state.mark_pending_sync(eng, command, "RECON", "PT-010")
    batch_id = state.get_pending_sync(eng)["batch_id"]

    ptt_path = eng / "state" / "ptt.md"
    ptt_path.write_text(
        ptt_path.read_text(encoding="utf-8")
        .replace("| PT-010 | [~] |", "| PT-010 | [x] |")
        .replace("| PT-011 | [ ] |", "| PT-011 | [~] |"),
        encoding="utf-8",
    )
    result = json.loads(
        service.handle_record_ptt(
            {"eng_dir": str(eng), "id": "PT-011", "status": "[~]", "note": f"review {batch_id}"}
        )
    )
    assert result["status"] == "error"
    assert "does not match batch task" in result["error"]


def test_appending_work_invalidates_an_earlier_review(tmp_path: Path) -> None:
    eng = _engagement(tmp_path)
    state.mark_pending_sync(eng, "nmap -p 80 10.10.10.10", "RECON", "PT-010")
    state.mark_ptt_reviewed(eng, "PT-010", "review")
    state.mark_pending_sync(eng, "nmap -p 443 10.10.10.10", "RECON", "PT-010")
    assert state.get_pending_sync(eng)["ptt_reviewed"] is False
