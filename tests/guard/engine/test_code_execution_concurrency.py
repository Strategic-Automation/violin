"""Tests for Violin's execute_code audit and receipt persistence."""

from __future__ import annotations

import json
import threading
from concurrent.futures import ThreadPoolExecutor

import pytest

from plugins.violin_guard.engine import code_execution_audit
from plugins.violin_guard.hooks import (
    _on_session_finalize_hook,
    _post_tool_call_hook,
    _pre_tool_call_hook,
)
from tests.guard.engine._code_execution_helpers import (
    _code,
    _engagement,
)


def test_execute_code_requires_tool_call_id_before_writing_intent(tmp_path) -> None:
    eng = _engagement(tmp_path)
    blocked = _pre_tool_call_hook(tool_name="execute_code", args={"code": _code(eng)})

    assert blocked == {
        "action": "block",
        "message": "execute_code requires Hermes tool_call_id for receipt correlation",
    }
    assert not list((eng / "evidence" / "executions").glob("*-execute-code.json"))


@pytest.mark.parametrize("mismatch", ["source", "session"])
def test_execute_code_mismatched_completion_abandons_without_result(tmp_path, mismatch) -> None:
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
            args={
                "code": source + "# changed after dispatch\n" if mismatch == "source" else source
            },
            result=ResultMustNotBeInspected(),
            duration_ms=9,
            session_id="different" if mismatch == "session" else "test",
            tool_call_id="mismatched-completion",
        )

    abandoned = json.loads(manifest.read_text(encoding="utf-8"))
    assert abandoned["status"] == "abandoned"
    assert abandoned["audit_id"] == intent["audit_id"]
    assert abandoned["source_digest"] == intent["source_digest"]
    assert abandoned["command"] == intent["command"]
    assert "result" not in abandoned
    assert "must-not-be-persisted" not in manifest.read_text(encoding="utf-8")
    with pytest.raises(ValueError, match="intent receipt is missing"):
        _post_tool_call_hook(
            tool_name="execute_code",
            args={"code": source},
            result="must not be credited",
            session_id="test",
            tool_call_id="mismatched-completion",
        )


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
