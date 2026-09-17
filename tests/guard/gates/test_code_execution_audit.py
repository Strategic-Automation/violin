"""Tests for Violin's execute_code audit and receipt persistence."""

from __future__ import annotations

import copy
import json
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from plugins.violin_guard.core import bootstrap, state
from plugins.violin_guard.core import history as execution_history
from plugins.violin_guard.gates import code_execution_audit
from plugins.violin_guard.hooks import (
    _on_session_finalize_hook,
    _post_tool_call_hook,
    _pre_tool_call_hook,
)
from tests.guard.receipt_fixture import bind_active_task

_SCOPE = """targets:
  ip_addresses: ["10.10.10.10"]
  in_scope_urls: []
exclusions: {}
authorized_parties: ["test owner"]
authorisation:
  confirmed: true
rules_of_engagement:
  allowed_actions: [recon]
  forbidden_actions: []
engagement:
  name: audit-test
  date: "2026-07-16"
  type: authorised-pentest
  client: test
"""


def _engagement(tmp_path: Path) -> Path:
    eng = tmp_path / "engagement"
    assert bootstrap.init_engagement(eng, host="10.10.10.10") == 0
    (eng / "scope" / "scope.yaml").write_text(_SCOPE, encoding="utf-8")
    (eng / "state" / ".skill-loaded-test").write_text("skill-loaded: test\n", encoding="utf-8")
    ptt = eng / "state" / "ptt.md"
    ptt.write_text(
        ptt.read_text(encoding="utf-8").replace("| PT-010 | [ ] |", "| PT-010 | [~] |"),
        encoding="utf-8",
    )
    bind_active_task(eng, "test")
    return eng


def _code(eng, target="10.10.10.10") -> str:
    return (
        '# violin: {"eng_dir":"'
        + str(eng).replace("\\", "\\\\")
        + '","phase":"RECON","target":"'
        + target
        + '","session_id":"test"}\n'
        "print('local audit work')\n"
    )


def _complete_execute_code_result(
    eng: Path,
    result: object,
    *,
    tool_call_id: str,
    source_suffix: str = "",
) -> tuple[Path, dict, dict, str]:
    source = _code(eng) + source_suffix
    manifests_before = set((eng / "evidence" / "executions").glob("*-execute-code.json"))
    assert (
        _pre_tool_call_hook(
            tool_name="execute_code",
            args={"code": source},
            session_id="test",
            tool_call_id=tool_call_id,
        )
        is None
    )
    new_manifests = (
        set((eng / "evidence" / "executions").glob("*-execute-code.json")) - manifests_before
    )
    assert len(new_manifests) == 1
    manifest = new_manifests.pop()
    intent = json.loads(manifest.read_text(encoding="utf-8"))
    _post_tool_call_hook(
        tool_name="execute_code",
        args={"code": source},
        result=result,
        duration_ms=3,
        session_id="test",
        tool_call_id=tool_call_id,
    )
    completed = json.loads(manifest.read_text(encoding="utf-8"))
    return manifest, intent, completed, source


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
    assert "session_id via violin_status" in blocked["message"]


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


def test_execute_code_rejects_foreign_literal_target(tmp_path) -> None:
    eng = _engagement(tmp_path)
    source = _code(eng) + "url = 'https://10.10.10.11/admin'\n"
    blocked = _pre_tool_call_hook(
        tool_name="execute_code", args={"code": source}, tool_call_id="foreign-target"
    )
    assert blocked["action"] == "block"
    assert "differ from declared target" in blocked["message"]


def test_execute_code_local_find_paths_are_not_foreign_targets(tmp_path) -> None:
    """Local evidence path strings in code must not be flagged as foreign targets."""
    eng = _engagement(tmp_path)
    source = _code(eng) + (
        "local_files = ['evidence/findings.jsonl', 'state/hypotheses.md']\n"
        "for f in local_files: print('author', f)\n"
    )
    blocked = _pre_tool_call_hook(
        tool_name="execute_code",
        args={"code": source},
        session_id="test",
        tool_call_id="local-find-paths",
    )
    # FIND/evidence path strings must not be flagged as foreign targets: either the
    # hook returns None (no block) or its message avoids the foreign-target error.
    if blocked is not None:
        assert blocked.get("action") != "block" or "differ from declared target" not in blocked.get(
            "message", ""
        )


def test_execute_code_completion_without_intent_is_an_audit_error(tmp_path) -> None:
    eng = _engagement(tmp_path)
    with pytest.raises(ValueError, match="intent receipt is missing"):
        _post_tool_call_hook(
            tool_name="execute_code",
            args={"code": _code(eng)},
            result='{"result":"ok"}',
            duration_ms=1,
            tool_call_id="missing-intent",
        )


def test_execute_code_records_tool_errors(tmp_path) -> None:
    eng = _engagement(tmp_path)
    source = _code(eng)
    assert (
        _pre_tool_call_hook(
            tool_name="execute_code",
            args={"code": source},
            session_id="test",
            tool_call_id="error-call",
        )
        is None
    )
    raw_result = '{"error":"sandbox failed"}'
    _post_tool_call_hook(
        tool_name="execute_code",
        args={"code": source},
        result=raw_result,
        duration_ms=7,
        session_id="test",
        tool_call_id="error-call",
    )
    manifest = next((eng / "evidence" / "executions").glob("*-execute-code.json"))
    completed = json.loads(manifest.read_text(encoding="utf-8"))
    assert completed["status"] == "completed_with_error"
    assert completed["result"]["parsed_as_json"] is True
    assert completed["result"]["representation_type"] == "json"
    assert completed["result"]["value"] == raw_result
    history = (eng / "state" / "history.md").read_text(encoding="utf-8")
    assert "status=completed_with_error" in history
    assert "exit_code=1" in history


def test_execute_code_redacts_nested_secrets_without_mutating_input(tmp_path) -> None:
    eng = _engagement(tmp_path)
    private_key = (
        "-----BEGIN PRIVATE KEY-----\nprivate-key-material-1234567890\n-----END PRIVATE KEY-----"
    )
    jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signaturevalue"
    result = {
        "safe": "visible",
        "nested": [
            {
                "password": "password-value-123",
                "passwd": "passwd-value-123",
                "secret": "secret-value-123",
                "token": "token-value-123",
                "access_token": "access-value-123",
                "refresh_token": "refresh-value-123",
            },
            {
                "api_key": "api-key-value-123",
                "apikey": "apikey-value-123",
                "authorization": "Bearer structured-auth-value-123",
                "cookie": "session=cookie-value-123",
                "set-cookie": "sid=set-cookie-value-123",
            },
            {
                "message": "Authorization: Bearer loose-bearer-value-123",
                "jwt_value": jwt,
                "provider_value": "sk-live-provider-token-value-1234567890",
                "private_material": private_key,
            },
        ],
    }
    original = copy.deepcopy(result)

    manifest, _intent, completed, _source = _complete_execute_code_result(
        eng,
        result,
        tool_call_id="nested-redaction",
    )

    assert result == original
    result_record = completed["result"]
    assert result_record["parsed_as_json"] is True
    assert result_record["representation_type"] == "json"
    assert result_record["truncated"] is False
    assert result_record["original_size_bytes"] == len(
        json.dumps(
            original,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    )
    assert result_record["stored_size_bytes"] == len(result_record["value"].encode("utf-8"))
    stored = json.loads(result_record["value"])
    assert stored["safe"] == "visible"
    for key in (
        "password",
        "passwd",
        "secret",
        "token",
        "access_token",
        "refresh_token",
    ):
        assert stored["nested"][0][key] == "[REDACTED]"
    for key in ("api_key", "apikey", "authorization", "cookie", "set-cookie"):
        assert stored["nested"][1][key] == "[REDACTED]"
    assert "loose-bearer-value-123" not in stored["nested"][2]["message"]
    assert stored["nested"][2]["jwt_value"] == "[REDACTED_JWT]"
    assert stored["nested"][2]["provider_value"] == "[REDACTED_TOKEN]"
    assert stored["nested"][2]["private_material"] == "[REDACTED_PRIVATE_KEY]"

    persisted = manifest.read_text(encoding="utf-8")
    history = (eng / "state" / "history.md").read_text(encoding="utf-8")
    for secret in (
        "password-value-123",
        "passwd-value-123",
        "secret-value-123",
        "token-value-123",
        "access-value-123",
        "refresh-value-123",
        "api-key-value-123",
        "apikey-value-123",
        "structured-auth-value-123",
        "cookie-value-123",
        "set-cookie-value-123",
        "loose-bearer-value-123",
        jwt,
        "sk-live-provider-token-value-1234567890",
        "private-key-material-1234567890",
    ):
        assert secret not in persisted
        assert secret not in history


@pytest.mark.parametrize(
    ("raw_result", "secret"),
    [
        ('prefix {"password":"dummy-password-123"}', "dummy-password-123"),
        ('{"access_token":"dummy-access-token-123", invalid}', "dummy-access-token-123"),
        (
            '{"authorization":"Basic dummy-authorization-123", invalid}',
            "dummy-authorization-123",
        ),
        ("cookie=dummy-cookie-123", "dummy-cookie-123"),
        ('{"set-cookie":"sid=dummy-set-cookie-123", invalid}', "dummy-set-cookie-123"),
        ('{"private_key":"dummy-private-key-123", invalid}', "dummy-private-key-123"),
        (
            "prefix -----BEGIN PRIVATE KEY-----\ndummy-partial-private-key-123",
            "dummy-partial-private-key-123",
        ),
    ],
    ids=[
        "quoted-password",
        "quoted-access-token",
        "quoted-authorization",
        "cookie-assignment",
        "quoted-set-cookie",
        "quoted-private-key",
        "partial-private-key",
    ],
)
def test_execute_code_redacts_named_secrets_in_non_json_text(
    tmp_path,
    raw_result,
    secret,
) -> None:
    eng = _engagement(tmp_path)

    manifest, _intent, completed, _source = _complete_execute_code_result(
        eng,
        raw_result,
        tool_call_id="non-json-secret-redaction",
    )

    assert completed["status"] == "completed_with_error"
    assert completed["result"]["parsed_as_json"] is False
    assert secret not in completed["result"]["value"]
    assert secret not in manifest.read_text(encoding="utf-8")


def test_execute_code_normalizes_unpaired_json_surrogate(tmp_path) -> None:
    eng = _engagement(tmp_path)
    raw_result = r'"\ud800"'

    manifest, _intent, completed, _source = _complete_execute_code_result(
        eng,
        raw_result,
        tool_call_id="unpaired-json-surrogate",
    )

    assert completed["status"] == "completed"
    assert completed["result"]["parsed_as_json"] is True
    assert completed["result"]["representation_type"] == "json"
    assert completed["result"]["value"] == raw_result
    assert json.loads(manifest.read_text(encoding="utf-8"))["result"] == completed["result"]


@pytest.mark.parametrize(
    ("raw_result", "parsed_as_json", "representation_type", "expected_value", "status"),
    [
        ("plain non-JSON result", False, "text", "plain non-JSON result", "completed_with_error"),
        ("", False, "text", "", "completed_with_error"),
        (None, True, "json", "null", "completed"),
    ],
)
def test_execute_code_persists_non_json_and_empty_results(
    tmp_path,
    raw_result,
    parsed_as_json,
    representation_type,
    expected_value,
    status,
) -> None:
    eng = _engagement(tmp_path)

    _manifest, _intent, completed, _source = _complete_execute_code_result(
        eng,
        raw_result,
        tool_call_id=f"result-shape-{representation_type}-{type(raw_result).__name__}",
    )

    result_record = completed["result"]
    original_text = raw_result if isinstance(raw_result, str) else "null"
    assert completed["status"] == status
    assert result_record["parsed_as_json"] is parsed_as_json
    assert result_record["representation_type"] == representation_type
    assert result_record["original_size_bytes"] == len(original_text.encode("utf-8"))
    assert result_record["stored_size_bytes"] == len(expected_value.encode("utf-8"))
    assert result_record["truncated"] is False
    assert result_record["value"] == expected_value


@pytest.mark.parametrize(
    ("raw_result", "parsed_as_json", "representation_type"),
    [
        (
            json.dumps(
                {
                    "password": "oversized-secret-value",
                    "payload": "é" * (33 * 1024),
                },
                ensure_ascii=False,
            ),
            True,
            "json",
        ),
        ("plain:" + "é" * (33 * 1024), False, "text"),
    ],
    ids=["json", "text"],
)
def test_execute_code_truncates_oversized_results_deterministically(
    tmp_path,
    raw_result,
    parsed_as_json,
    representation_type,
) -> None:
    eng = _engagement(tmp_path)

    first_manifest, _first_intent, first, _first_source = _complete_execute_code_result(
        eng,
        raw_result,
        tool_call_id=f"oversized-{representation_type}-first",
        source_suffix="print('first oversized result')\n",
    )
    second_manifest, _second_intent, second, _second_source = _complete_execute_code_result(
        eng,
        raw_result,
        tool_call_id=f"oversized-{representation_type}-second",
        source_suffix="print('second oversized result')\n",
    )

    first_record = first["result"]
    second_record = second["result"]
    assert first_record["parsed_as_json"] is parsed_as_json
    assert first_record["representation_type"] == representation_type
    assert first_record["original_size_bytes"] == len(raw_result.encode("utf-8"))
    assert first_record["max_stored_size_bytes"] == code_execution_audit.MAX_STORED_RESULT_BYTES
    assert first_record["truncated"] is True
    assert first_record["stored_size_bytes"] == len(first_record["value"].encode("utf-8"))
    assert first_record["stored_size_bytes"] <= code_execution_audit.MAX_STORED_RESULT_BYTES
    assert second_record["value"] == first_record["value"]
    assert second_record["stored_size_bytes"] == first_record["stored_size_bytes"]
    assert second_record["truncated"] is True
    assert "oversized-secret-value" not in first_manifest.read_text(encoding="utf-8")
    assert "oversized-secret-value" not in second_manifest.read_text(encoding="utf-8")


def test_execute_code_requires_tool_call_id_before_writing_intent(tmp_path) -> None:
    eng = _engagement(tmp_path)
    blocked = _pre_tool_call_hook(tool_name="execute_code", args={"code": _code(eng)})

    assert blocked == {
        "action": "block",
        "message": "execute_code requires Hermes tool_call_id for receipt correlation",
    }
    assert not list((eng / "evidence" / "executions").glob("*-execute-code.json"))


def test_execute_code_mismatched_completion_abandons_without_result(tmp_path) -> None:
    class ResultMustNotBeInspected:
        marker = "must-not-be-persisted"

        def __str__(self) -> str:
            raise AssertionError("mismatched completion result was inspected")

    eng = _engagement(tmp_path)
    source = _code(eng)
    assert (
        _pre_tool_call_hook(
            tool_name="execute_code",
            args={"code": source},
            session_id="test",
            tool_call_id="mismatched-completion",
        )
        is None
    )
    manifest = next((eng / "evidence" / "executions").glob("*-execute-code.json"))
    intent = json.loads(manifest.read_text(encoding="utf-8"))

    with pytest.raises(ValueError, match="does not match its intent receipt"):
        _post_tool_call_hook(
            tool_name="execute_code",
            args={"code": source + "# changed after dispatch\n"},
            result=ResultMustNotBeInspected(),
            duration_ms=9,
            session_id="test",
            tool_call_id="mismatched-completion",
        )

    abandoned = json.loads(manifest.read_text(encoding="utf-8"))
    assert abandoned["status"] == "abandoned"
    assert abandoned["audit_id"] == intent["audit_id"]
    assert abandoned["source_digest"] == intent["source_digest"]
    assert abandoned["command"] == intent["command"]
    assert "result" not in abandoned
    assert "must-not-be-persisted" not in manifest.read_text(encoding="utf-8")


def test_parallel_execute_code_calls_correlate_by_tool_call_id(tmp_path) -> None:
    eng = _engagement(tmp_path)
    first = _code(eng) + "print('first call')\n"
    second = _code(eng) + "print('second call')\n"

    assert (
        _pre_tool_call_hook(
            tool_name="execute_code",
            args={"code": first},
            session_id="test",
            tool_call_id="parallel-1",
        )
        is None
    )
    assert (
        _pre_tool_call_hook(
            tool_name="execute_code",
            args={"code": second},
            session_id="test",
            tool_call_id="parallel-2",
        )
        is None
    )

    def complete(source: str, result: str, duration_ms: int, tool_call_id: str) -> None:
        _post_tool_call_hook(
            tool_name="execute_code",
            args={"code": source},
            result=result,
            duration_ms=duration_ms,
            session_id="test",
            tool_call_id=tool_call_id,
        )

    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [
            pool.submit(complete, first, '{"result":"first"}', 11, "parallel-1"),
            pool.submit(complete, second, '{"result":"second"}', 22, "parallel-2"),
        ]
        for future in futures:
            future.result()

    receipts = [
        json.loads(path.read_text(encoding="utf-8"))
        for path in (eng / "evidence" / "executions").glob("*-execute-code.json")
    ]
    expected = {
        code_execution_audit.source_digest(first): ("first", 11),
        code_execution_audit.source_digest(second): ("second", 22),
    }
    assert len(receipts) == 2
    for receipt in receipts:
        expected_value, expected_duration = expected[receipt["source_digest"]]
        assert receipt["status"] == "completed"
        assert receipt["duration_ms"] == expected_duration
        assert json.loads(receipt["result"]["value"])["result"] == expected_value


def test_execute_code_concurrent_completions_preserve_first_terminal_result(tmp_path) -> None:
    eng = _engagement(tmp_path)
    source = _code(eng) + "print('completion race')\n"
    _metadata, manifest = code_execution_audit.prepare_execution(source)
    intent = json.loads(manifest.read_text(encoding="utf-8"))
    start = threading.Barrier(2)

    def complete(value: str) -> None:
        start.wait()
        code_execution_audit.record_completion(
            source,
            {"result": value},
            5,
            receipt_path=manifest,
        )

    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(complete, "first"), pool.submit(complete, "second")]
        errors = []
        for future in futures:
            try:
                future.result()
            except ValueError as exc:
                errors.append(str(exc))

    assert len(errors) == 1
    assert "already finalized" in errors[0]
    terminal = json.loads(manifest.read_text(encoding="utf-8"))
    assert terminal["status"] == "completed"
    assert terminal["audit_id"] == intent["audit_id"]
    assert terminal["source_digest"] == intent["source_digest"]
    assert terminal["command"] == intent["command"]
    assert json.loads(terminal["result"]["value"])["result"] in {"first", "second"}
    history = (eng / "state" / "history.md").read_text(encoding="utf-8")
    assert history.count(manifest.relative_to(eng).as_posix()) == 1


def test_execute_code_completion_and_abandonment_serialize_one_terminal_manifest(tmp_path) -> None:
    eng = _engagement(tmp_path)
    source = _code(eng) + "print('completion race')\n"
    _metadata, manifest = code_execution_audit.prepare_execution(source)
    intent = json.loads(manifest.read_text(encoding="utf-8"))
    start = threading.Barrier(2)

    def complete() -> None:
        start.wait()
        code_execution_audit.record_completion(
            source,
            {"result": "completed"},
            5,
            receipt_path=manifest,
        )

    def abandon() -> None:
        start.wait()
        code_execution_audit.abandon_execution(manifest, "concurrent abandonment")

    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(complete), pool.submit(abandon)]
        errors = []
        for future in futures:
            try:
                future.result()
            except ValueError as exc:
                errors.append(str(exc))

    assert not errors or all("already finalized" in error for error in errors)
    terminal = json.loads(manifest.read_text(encoding="utf-8"))
    assert terminal["status"] in {"completed", "abandoned"}
    assert terminal["audit_id"] == intent["audit_id"]
    assert terminal["source_digest"] == intent["source_digest"]
    assert terminal["command"] == intent["command"]
    if terminal["status"] == "completed":
        assert json.loads(terminal["result"]["value"])["result"] == "completed"
    else:
        assert "result" not in terminal
    history = (eng / "state" / "history.md").read_text(encoding="utf-8")
    assert history.count(manifest.relative_to(eng).as_posix()) == 1


def test_session_finalize_abandons_unfinished_execute_code_receipt(tmp_path) -> None:
    eng = _engagement(tmp_path)
    source = _code(eng)
    assert (
        _pre_tool_call_hook(
            tool_name="execute_code",
            args={"code": source},
            session_id="test",
            tool_call_id="abandoned-call",
        )
        is None
    )

    _on_session_finalize_hook(session_id="test", eng_dir=str(eng))

    manifest = next((eng / "evidence" / "executions").glob("*-execute-code.json"))
    receipt = json.loads(manifest.read_text(encoding="utf-8"))
    assert receipt["status"] == "abandoned"
    assert "result" not in receipt
    with pytest.raises(ValueError, match="intent receipt is missing for tool_call_id"):
        _post_tool_call_hook(
            tool_name="execute_code",
            args={"code": source},
            result='{"result":"late"}',
            session_id="test",
            tool_call_id="abandoned-call",
        )
