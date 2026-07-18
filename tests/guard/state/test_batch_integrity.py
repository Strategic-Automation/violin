"""Pending-sync batches must stay bound to their original PTT task."""

from __future__ import annotations

import json
from pathlib import Path

from plugins.violin_guard import bootstrap, history, service, state


def _engagement(tmp_path: Path) -> Path:
    eng = tmp_path / "10.10.10.10-2026-07-13"
    assert bootstrap.init_engagement(eng, host="10.10.10.10") == 0
    ptt_path = eng / "state" / "ptt.md"
    ptt_path.write_text(
        ptt_path.read_text(encoding="utf-8").replace("| PT-010 | [ ] |", "| PT-010 | [~] |"),
        encoding="utf-8",
    )
    return eng


def test_record_ptt_refuses_to_reconcile_a_pending_batch(tmp_path: Path) -> None:
    eng = _engagement(tmp_path)
    command = "nmap -p 80 10.10.10.10"
    history.append_history(eng, command, "RECON", 0, "evidence/executions/test.json")
    state.mark_pending_sync(eng, command, "RECON", "PT-010")
    ptt_path = eng / "state" / "ptt.md"
    ptt_path.write_text(
        ptt_path.read_text(encoding="utf-8")
        .replace("| PT-010 | [~] |", "| PT-010 | [x] |")
        .replace("| PT-011 | [ ] |", "| PT-011 | [~] |"),
        encoding="utf-8",
    )
    result = json.loads(
        service.handle_record_ptt(
            {
                "eng_dir": str(eng),
                "id": "PT-011",
                "status": "[~]",
                "note": "review",
                "skill": "pentest",
                "technique": "recon",
            }
        )
    )
    assert result["status"] == "error"
    assert "violin_review_batch" in result["error"]
    assert state.get_pending_sync(eng)["ptt_task_id"] == "PT-010"


def test_appending_work_invalidates_an_earlier_review(tmp_path: Path) -> None:
    eng = _engagement(tmp_path)
    state.mark_pending_sync(eng, "nmap -p 80 10.10.10.10", "RECON", "PT-010")
    state.mark_ptt_reviewed(eng, "PT-010", "review")
    state.mark_pending_sync(eng, "nmap -p 443 10.10.10.10", "RECON", "PT-010")
    assert state.get_pending_sync(eng)["ptt_reviewed"] is False


def _completed_batch_with_active_replacement(eng: Path, replacement: str = "PT-011") -> str:
    command = "nmap -p 80 10.10.10.10"
    history.append_history(eng, command, "RECON", 0, "evidence/executions/test.json")
    state.mark_pending_sync(eng, command, "RECON", "PT-010")
    ptt_path = eng / "state" / "ptt.md"
    ptt_path.write_text(
        ptt_path.read_text(encoding="utf-8")
        .replace("| PT-010 | [~] |", "| PT-010 | [x] |")
        .replace(f"| {replacement} | [ ] |", f"| {replacement} | [~] |"),
        encoding="utf-8",
    )
    return state.get_pending_sync(eng)["batch_id"]


def test_confirmed_rebind_is_audited_but_does_not_review_or_unlock(tmp_path: Path) -> None:
    eng = _engagement(tmp_path)
    batch_id = _completed_batch_with_active_replacement(eng)

    result = json.loads(
        service.handle_rebind_pending_batch(
            {
                "eng_dir": str(eng),
                "batch_id": batch_id,
                "current_task_id": "PT-010",
                "replacement_task_id": "PT-011",
                "note": "Move completed recon evidence to the corrected task",
                "confirm": True,
            }
        )
    )

    assert result["status"] == "ok", result
    pending = state.get_pending_sync(eng)
    assert pending["ptt_task_id"] == "PT-011"
    assert pending["ptt_reviewed"] is False
    assert state.has_pending_sync(eng)
    sync_data = json.loads((eng / "state" / "sync.json").read_text(encoding="utf-8"))
    assert sync_data["rebind_audit"][-1]["old_task_id"] == "PT-010"
    assert sync_data["rebind_audit"][-1]["new_task_id"] == "PT-011"


def test_rebind_requires_confirmation_and_current_batch_identity(tmp_path: Path) -> None:
    eng = _engagement(tmp_path)
    batch_id = _completed_batch_with_active_replacement(eng)
    base = {
        "eng_dir": str(eng),
        "batch_id": batch_id,
        "current_task_id": "PT-010",
        "replacement_task_id": "PT-011",
        "note": "operator-reviewed recovery",
    }

    unconfirmed = json.loads(service.handle_rebind_pending_batch({**base, "confirm": False}))
    assert "confirm=true" in unconfirmed["error"]
    stale = json.loads(
        service.handle_rebind_pending_batch({**base, "batch_id": "stale", "confirm": True})
    )
    assert "stale batch id" in stale["error"]
    mismatch = json.loads(
        service.handle_rebind_pending_batch({**base, "current_task_id": "PT-999", "confirm": True})
    )
    assert "does not match batch task" in mismatch["error"]


def test_rebind_rejects_incomplete_or_phase_incompatible_batch(tmp_path: Path) -> None:
    eng = _engagement(tmp_path)
    state.mark_pending_sync(eng, "nmap -p 80 10.10.10.10", "RECON", "PT-010")
    pending = state.get_pending_sync(eng)
    incomplete = json.loads(
        service.handle_rebind_pending_batch(
            {
                "eng_dir": str(eng),
                "batch_id": pending["batch_id"],
                "current_task_id": "PT-010",
                "replacement_task_id": "PT-011",
                "note": "too early",
                "confirm": True,
            }
        )
    )
    assert "not yet in exact history" in incomplete["error"]

    eng2 = _engagement(tmp_path / "other")
    batch_id = _completed_batch_with_active_replacement(eng2, "PT-042")
    incompatible = json.loads(
        service.handle_rebind_pending_batch(
            {
                "eng_dir": str(eng2),
                "batch_id": batch_id,
                "current_task_id": "PT-010",
                "replacement_task_id": "PT-042",
                "note": "wrong phase",
                "confirm": True,
            }
        )
    )
    assert "not phase-compatible" in incompatible["error"]
