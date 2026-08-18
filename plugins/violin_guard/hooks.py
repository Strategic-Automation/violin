"""Hermes runtime lifecycle and tool policy hooks."""

from __future__ import annotations

import contextlib
import json
import threading
from pathlib import Path
from typing import Any

from .core import ptt, state
from .core.skill_receipts import (
    advance_context_generation,
    binding_readiness,
    record_binding_turn,
    record_delivery_turn,
)
from .gates import code_execution_audit
from .gates.terminal_policy import block_terminal_command

_SESSION_ENGAGEMENTS: dict[str, str] = {}
_EXECUTE_CODE_RECEIPTS: dict[str, tuple[str, str]] = {}
_EXECUTE_CODE_RECEIPTS_LOCK = threading.Lock()
_TARGET_TOOLS = {
    "violin_exec",
    "violin_exec_burst",
}
_BROWSER_TARGET_TOOLS = {
    "browser_navigate",
    "browser_click",
    "browser_type",
    "browser_select",
    "browser_scroll",
}


def _check_turn_binding(tool_name: str, args: dict[str, Any], hook: dict[str, Any]) -> str | None:
    """Stop target/browser activity until an earlier-turn receipt is bound."""
    session_id = str(hook.get("session_id") or args.get("session_id") or "")
    eng_dir = str(args.get("eng_dir") or _SESSION_ENGAGEMENTS.get(session_id) or "")
    if not eng_dir:
        return (
            f"{tool_name} needs an engagement associated through violin_status or a Violin tool "
            "before browser or target activity is allowed"
        )
    tasks = ptt.parse_ptt(Path(eng_dir) / "state" / "ptt.md")
    active = ptt.find_active_task(tasks)
    if not active:
        return "target activity requires exactly one active [~] PTT task"
    binding, reason = binding_readiness(eng_dir, task_id=active.id, session_id=session_id)
    if reason:
        return f"target activity blocked: {reason}; select and prepare a routed skill first"
    api_request_id = str(hook.get("api_request_id") or "")
    receipt_request_ids = {
        str(binding.get("bound_api_request_id") or ""),
        str(binding.get("delivered_api_request_id") or ""),
    }
    receipt_request_ids.discard("")
    same_model_call = bool(api_request_id and api_request_id in receipt_request_ids)
    if not receipt_request_ids:
        turn_id = str(hook.get("turn_id") or "")
        same_model_call = bool(
            turn_id
            and turn_id
            in {
                str(binding.get("bound_turn_id") or ""),
                str(binding.get("delivered_turn_id") or ""),
            }
        )
    if same_model_call:
        return (
            "target activity is blocked in the same model call as skill delivery/binding; "
            "process the tool result and retry in the next model continuation"
        )
    return None


def _abandon_execute_code_receipts(session_id: object, reason: str) -> None:
    session = str(session_id or "")
    if not session:
        return
    with _EXECUTE_CODE_RECEIPTS_LOCK:
        abandoned: list[str] = []
        for key, (owner, receipt) in list(_EXECUTE_CODE_RECEIPTS.items()):
            if owner == session:
                _EXECUTE_CODE_RECEIPTS.pop(key)
                abandoned.append(receipt)
    for receipt in abandoned:
        with contextlib.suppress(Exception):
            code_execution_audit.abandon_execution(receipt, reason)


def _pre_tool_call_hook(
    tool_name: str | None = None, args: Any = None, **kwargs: Any
) -> dict[str, str] | None:
    """Apply the raw-terminal classifier and the execute-code audit gate."""
    args = args if isinstance(args, dict) else {}
    session_id = str(kwargs.get("session_id") or args.get("session_id") or "")
    eng_dir = str(args.get("eng_dir") or "")
    if session_id and eng_dir:
        _SESSION_ENGAGEMENTS[session_id] = eng_dir
        state.record_session_id(eng_dir, session_id)
    if tool_name in _TARGET_TOOLS or tool_name in _BROWSER_TARGET_TOOLS:
        blocked = _check_turn_binding(tool_name or "", args, kwargs)
        if blocked:
            return {"action": "block", "message": blocked}
    if tool_name == "execute_code":
        tool_call_id = str(kwargs.get("tool_call_id") or "").strip()
        if not tool_call_id:
            return {
                "action": "block",
                "message": "execute_code requires Hermes tool_call_id for receipt correlation",
            }
        with _EXECUTE_CODE_RECEIPTS_LOCK:
            if tool_call_id in _EXECUTE_CODE_RECEIPTS:
                return {
                    "action": "block",
                    "message": f"execute_code tool_call_id is already active: {tool_call_id}",
                }
            try:
                metadata, receipt = code_execution_audit.prepare_execution(args.get("code"))
            except Exception as exc:
                return {"action": "block", "message": str(exc)}
            receipt_session = session_id or metadata["session_id"]
            _EXECUTE_CODE_RECEIPTS[tool_call_id] = (receipt_session, str(receipt))
        return None
    if tool_name != "terminal":
        return None
    message = block_terminal_command(args.get("command", ""))
    return None if message is None else {"action": "block", "message": message}


def _post_tool_call_hook(
    tool_name: str | None = None,
    args: Any = None,
    result: Any = None,
    duration_ms: int = 0,
    **kwargs: Any,
) -> None:
    """Write the auditable execute-code source receipt after dispatch."""
    if tool_name == "execute_code" and isinstance(args, dict):
        tool_call_id = str(kwargs.get("tool_call_id") or "").strip()
        if not tool_call_id:
            raise ValueError("execute_code completion is missing Hermes tool_call_id")
        session_id = str(kwargs.get("session_id") or "")
        with _EXECUTE_CODE_RECEIPTS_LOCK:
            pending = _EXECUTE_CODE_RECEIPTS.get(tool_call_id)
            if pending is None:
                raise ValueError("execute_code intent receipt is missing for tool_call_id")
            receipt_session, receipt = pending
            if session_id and receipt_session and session_id != receipt_session:
                raise ValueError(
                    "execute_code completion session does not match its intent receipt"
                )
            _EXECUTE_CODE_RECEIPTS.pop(tool_call_id)
        try:
            code_execution_audit.record_completion(
                args.get("code"), result, duration_ms, receipt_path=receipt
            )
        except Exception as exc:
            code_execution_audit.abandon_execution(receipt, f"completion failed: {exc}")
            raise
    if tool_name in {"web_search", "web_extract"}:
        session_id = str(kwargs.get("session_id") or "")
        eng_dir = _SESSION_ENGAGEMENTS.get(session_id)
        if eng_dir:
            with contextlib.suppress(Exception):
                state.record_research_attempt(eng_dir, tool_name, not bool(result is None))

    if tool_name not in {"violin_record_ptt", "violin_review_batch"}:
        return
    args = args if isinstance(args, dict) else {}
    eng_dir = str(args.get("eng_dir") or "")
    turn_id = str(kwargs.get("turn_id") or "")
    api_request_id = str(kwargs.get("api_request_id") or "")
    if not eng_dir or (not turn_id and not api_request_id):
        return
    try:
        payload = json.loads(result) if isinstance(result, str) else result
        if not isinstance(payload, dict):
            return
        skill = payload.get("skill") or {}
        delivery_id = str(skill.get("delivery_id") or "")
        if payload.get("status") == "skill_prepared" and delivery_id:
            record_delivery_turn(
                eng_dir,
                delivery_id=delivery_id,
                turn_id=turn_id,
                api_request_id=api_request_id,
            )
        task_id = ""
        if tool_name == "violin_record_ptt":
            task_id = str(payload.get("task_id") or "")
        elif tool_name == "violin_review_batch":
            task_id = str(payload.get("binding_task_id") or "")
        if payload.get("status") == "ok" and task_id:
            record_binding_turn(
                eng_dir,
                task_id=task_id,
                turn_id=turn_id,
                api_request_id=api_request_id,
            )
    except Exception:
        return


def _pre_llm_call_hook(session_id: Any = None, eng_dir: Any = None, **kwargs: Any) -> None:
    """Lifecycle heartbeat: tick the message counter before each LLM call."""
    if eng_dir:
        with contextlib.suppress(Exception):
            state.tick_message(str(eng_dir))
            state.record_session_id(str(eng_dir), session_id)
            if session_id:
                _SESSION_ENGAGEMENTS[str(session_id)] = str(eng_dir)


def _on_session_reset_hook(session_id: Any = None, eng_dir: Any = None, **kwargs: Any) -> None:
    """Hook: session reset (context compression, /goal set, etc.)."""
    _abandon_execute_code_receipts(session_id, "session reset before tool completion")
    eng_dir = eng_dir or (_SESSION_ENGAGEMENTS.get(str(session_id)) if session_id else None)
    if eng_dir:
        with contextlib.suppress(Exception):
            state.tick_message(str(eng_dir))
            advance_context_generation(str(eng_dir), str(session_id or "reset"))


def _on_session_finalize_hook(session_id: Any = None, eng_dir: Any = None, **kwargs: Any) -> None:
    """Hook: session finalize."""
    _abandon_execute_code_receipts(session_id, "session finalized before tool completion")
    eng_dir = eng_dir or (_SESSION_ENGAGEMENTS.get(str(session_id)) if session_id else None)
    if eng_dir:
        with contextlib.suppress(Exception):
            pending = state.has_pending_sync(str(eng_dir))
            if pending:
                state.set_heartbeat_pending(
                    str(eng_dir),
                    "session finalized with a pending sync lock; run violin_review_batch",
                )


__all__ = [
    "_on_session_finalize_hook",
    "_on_session_reset_hook",
    "_post_tool_call_hook",
    "_pre_llm_call_hook",
    "_pre_tool_call_hook",
]
