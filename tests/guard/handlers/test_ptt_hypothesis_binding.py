"""PTT hypothesis binding validates existence before any reservation or mutation."""

import json

import pytest

from plugins.violin_guard.core.engagement import bootstrap, state
from plugins.violin_guard.handlers import ptt_handlers


@pytest.mark.parametrize("task_id", ["PT-010", "PT-030"])
def test_missing_hypothesis_rejected_before_ptt_or_binding_mutation(tmp_path, monkeypatch, task_id):
    assert bootstrap.init_engagement(tmp_path, host="10.10.10.10") == 0
    state.get_pending_sync(tmp_path)  # Acquire the normal read lock before the snapshot.
    before = {
        path.relative_to(tmp_path): path.read_bytes()
        for path in tmp_path.rglob("*")
        if path.is_file()
    }

    def unexpected(*args, **kwargs):
        pytest.fail("invalid hypothesis must not reserve a skill or bind a task")

    monkeypatch.setattr(ptt_handlers, "_prepare_record_ptt_delivery", unexpected)
    monkeypatch.setattr(ptt_handlers, "bind_task", unexpected)
    result = json.loads(
        ptt_handlers.handle_record_ptt(
            {
                "eng_dir": str(tmp_path),
                "id": task_id,
                "status": "[~]",
                "note": "Begin probe",
                "skill": "pentest",
                "technique": "probe",
                "hypothesis_id": "H-999",
            }
        )
    )
    assert result["status"] == "error"
    assert "does not exist" in result["error"]
    assert "violin_record_hypothesis" in result["error"]
    after = {
        path.relative_to(tmp_path): path.read_bytes()
        for path in tmp_path.rglob("*")
        if path.is_file()
    }
    assert after == before


def test_existing_canonical_hypothesis_reaches_normal_skill_reservation(tmp_path, monkeypatch):
    assert bootstrap.init_engagement(tmp_path, host="10.10.10.10") == 0
    (tmp_path / "hypotheses.md").write_text(
        "# Hypotheses\n\n## Active Theories\n\n### H-001: Probe\n- Status: Candidate\n- Vulnerability Class: idor\n",
        encoding="utf-8",
    )
    captured = []
    monkeypatch.setattr(
        ptt_handlers,
        "_prepare_record_ptt_delivery",
        lambda *args: captured.append(args) or (None, None, '{"status":"reserved"}'),
    )
    result = json.loads(
        ptt_handlers.handle_record_ptt(
            {
                "eng_dir": str(tmp_path),
                "id": "PT-030",
                "status": "[~]",
                "note": "Begin probe",
                "skill": "identity-auth",
                "technique": "probe",
                "hypothesis_id": "H-001",
            }
        )
    )
    assert result["status"] == "reserved"
    assert len(captured) == 1
