"""Tests for Violin's execute_code audit and receipt persistence."""

from __future__ import annotations

import json

from plugins.violin_guard.core.engagement import state
from plugins.violin_guard.core.evidence import history as execution_history
from plugins.violin_guard.engine import code_execution_audit
from plugins.violin_guard.hooks import (
    _post_tool_call_hook,
    _pre_tool_call_hook,
)
from tests.guard.engine._code_execution_helpers import (
    _code,
    _engagement,
    _no_active_task_engagement,
)


def test_local_execute_code_runs_with_no_active_ptt_task(tmp_path) -> None:
    eng = _no_active_task_engagement(tmp_path)
    source = _code(eng) + "print('local audit work')\n"
    assert (
        _pre_tool_call_hook(
            tool_name="execute_code",
            args={"code": source},
            session_id="test",
            tool_call_id="no-active-task-local",
        )
        is None
    )


def test_target_touching_execute_code_still_requires_active_ptt_task(tmp_path) -> None:
    eng = _no_active_task_engagement(tmp_path)
    source = _code(eng) + "import requests\nrequests.get('https://10.10.10.10')\n"
    blocked = _pre_tool_call_hook(
        tool_name="execute_code",
        args={"code": source},
        session_id="test",
        tool_call_id="no-active-task-target",
    )
    assert blocked["action"] == "block"
    assert "violin_record_ptt" in blocked["message"]


def test_execute_code_requires_valid_metadata(tmp_path) -> None:
    blocked = _pre_tool_call_hook(
        tool_name="execute_code",
        args={"code": "print('missing header')"},
        tool_call_id="invalid-header",
    )
    assert blocked["action"] == "block"
    assert "first-line metadata" in blocked["message"]

    blocked = _pre_tool_call_hook(
        tool_name="execute_code",
        args={"code": _code(_engagement(tmp_path), "10.10.10.11")},
        tool_call_id="invalid-target",
    )
    assert blocked["action"] == "block"
    assert "Violin guard" in blocked["message"]


def test_execute_code_missing_fields_surfaces_header_schema(tmp_path) -> None:
    code = '# violin: {"eng_dir":"/tmp/test"}\nprint(1)'
    blocked = _pre_tool_call_hook(
        tool_name="execute_code", args={"code": code}, tool_call_id="missing-fields"
    )
    assert blocked["action"] == "block"
    assert "Header format" in blocked["message"]
    # An unusable header must restate the documented header with an example line.
    assert '# violin: {"eng_dir":"/engagements/' in blocked["message"]


def test_execute_code_accepts_documented_two_field_header(tmp_path) -> None:
    eng = _engagement(tmp_path)
    code = (
        '# violin: {"eng_dir":"'
        + str(eng).replace("\\", "\\\\")
        + '","phase":"RECON"}\nprint("local audit work")\n'
    )
    assert (
        _pre_tool_call_hook(
            tool_name="execute_code",
            args={"code": code},
            session_id="test",
            tool_call_id="documented-two-field",
        )
        is None
    )
    intent = json.loads(
        next((eng / "evidence" / "executions").glob("*-execute-code.json")).read_text(
            encoding="utf-8"
        )
    )
    # target and session_id are filled from engagement state.
    assert intent["target"] == "10.10.10.10"
    assert intent["session_id"] == "test"
    assert intent["execution_class"] == "local_analysis"


def test_execute_code_is_validated_and_recorded(tmp_path) -> None:
    eng = _engagement(tmp_path)
    source = _code(eng) + "import requests\nrequests.get('https://10.10.10.10')\n"
    assert (
        _pre_tool_call_hook(
            tool_name="execute_code",
            args={"code": source},
            session_id="test",
            tool_call_id="recorded-call",
        )
        is None
    )
    intent_receipts = list((eng / "evidence" / "executions").glob("*-execute-code.json"))
    assert len(intent_receipts) == 1
    intent = json.loads(intent_receipts[0].read_text(encoding="utf-8"))
    assert intent["status"] == "starting"
    assert intent["execution_class"] == "target_touching"
    assert intent["sync_accounted"] is True
    assert state.sync_credit_remaining(eng, "RECON") == 9
    assert state.has_pending_sync(eng)

    raw_result = '{"result":"ok"}'
    _post_tool_call_hook(
        tool_name="execute_code",
        args={"code": source},
        result=raw_result,
        duration_ms=42,
        session_id="test",
        tool_call_id="recorded-call",
    )

    completed = json.loads(intent_receipts[0].read_text(encoding="utf-8"))
    assert completed["audit_id"] == intent["audit_id"]
    assert completed["source_digest"] == intent["source_digest"]
    assert completed["command"] == intent["command"]
    assert completed["result"] == {
        "parsed_as_json": True,
        "representation_type": "json",
        "original_size_bytes": len(raw_result.encode("utf-8")),
        "stored_size_bytes": len(raw_result.encode("utf-8")),
        "max_stored_size_bytes": code_execution_audit.MAX_STORED_RESULT_BYTES,
        "truncated": False,
        "value": raw_result,
    }
    receipts = list((eng / "evidence" / "executions").glob("*-execute-code.py"))
    assert len(receipts) == 1
    assert receipts[0].read_text(encoding="utf-8") == source
    history = (eng / "state" / "history.md").read_text(encoding="utf-8")
    assert "execute_code class=target_touching sha256=" in history
    assert "status=completed" in history
    assert "exit_code=0" in history
    assert completed["evidence_paths"]["manifest"] in history
    assert raw_result not in history
    pending = state.get_pending_sync(eng)
    assert pending is not None
    pending_command = pending["commands"][0]["command"]
    assert "duration_ms=" not in pending_command
    assert execution_history.history_contains(eng, pending_command)
    runtime = state.read_json(eng / "state" / "runtime.json")
    accounting = runtime["sync"]["execution_accounts"][completed["audit_id"]]
    assert accounting["command"] == pending_command
    assert completed["audit_id"] in runtime["counts"]["execution_ids"]
    counts_before_retry = state.read_counts(eng)
    remaining_before_retry = state.sync_credit_remaining(eng, "RECON")
    state.commit_execution_start(
        eng,
        pending_command,
        completed["phase"],
        pending["ptt_task_id"],
        completed["audit_id"],
    )
    assert state.read_counts(eng) == counts_before_retry
    assert state.sync_credit_remaining(eng, "RECON") == remaining_before_retry
    assert len(state.get_pending_sync(eng)["commands"]) == len(pending["commands"])
    from plugins.violin_guard.handlers.ptt_rebind import _validate_pending_history
    from plugins.violin_guard.handlers.ptt_review import _validate_review_history

    _validate_review_history(str(eng), pending)
    _validate_pending_history(str(eng), pending)


def test_local_execute_code_is_recorded_without_target_sync_credit(tmp_path) -> None:
    eng = _engagement(tmp_path)
    source = _code(eng) + "import json\nprint(json.dumps({'local': True}))\n"
    before = state.sync_credit_remaining(eng, "RECON")

    assert (
        _pre_tool_call_hook(
            tool_name="execute_code",
            args={"code": source},
            session_id="test",
            tool_call_id="local-analysis",
        )
        is None
    )
    intent_receipts = list((eng / "evidence" / "executions").glob("*-execute-code.json"))
    assert len(intent_receipts) == 1
    intent = json.loads(intent_receipts[0].read_text(encoding="utf-8"))
    assert intent["execution_class"] == "local_analysis"
    assert intent["sync_accounted"] is False
    assert state.sync_credit_remaining(eng, "RECON") == before
    assert not state.has_pending_sync(eng)

    _post_tool_call_hook(
        tool_name="execute_code",
        args={"code": source},
        result='{"result":"ok"}',
        duration_ms=5,
        session_id="test",
        tool_call_id="local-analysis",
    )
    history = (eng / "state" / "history.md").read_text(encoding="utf-8")
    assert "execute_code class=local_analysis" in history


def test_local_execute_code_remains_available_when_target_credit_is_exhausted(tmp_path) -> None:
    eng = _engagement(tmp_path)
    for _ in range(state.sync_credit_limit("RECON")):
        state.spend_sync_credit(eng, "RECON")
    assert state.sync_credit_remaining(eng, "RECON") == 0

    source = _code(eng)
    assert (
        _pre_tool_call_hook(
            tool_name="execute_code",
            args={"code": source},
            session_id="test",
            tool_call_id="exhausted-local-analysis",
        )
        is None
    )
    _post_tool_call_hook(
        tool_name="execute_code",
        args={"code": source},
        result='{"result":"ok"}',
        duration_ms=1,
        session_id="test",
        tool_call_id="exhausted-local-analysis",
    )
    assert state.sync_credit_remaining(eng, "RECON") == 0
    assert not state.has_pending_sync(eng)
