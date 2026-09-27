"""Tests for execute_code result persistence and redaction."""

from __future__ import annotations

import copy
import json

import pytest

from plugins.violin_guard.engine import code_execution_audit
from tests.guard.engine.code_execution_audit_helpers import (
    _complete_execute_code_result,
    _engagement,
)


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
