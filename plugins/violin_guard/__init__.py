"""Violin guard plugin — typed guard tools + forced check-command gate + doc-sync.

Hermes plugin registration entry point.
"""

from __future__ import annotations

import contextlib
import json
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ValidationError

from . import (
    code_execution_audit,
    handlers,  # noqa: E402
    ptt,
    schemas,  # noqa: E402
    state,  # noqa: E402
)
from .skill_receipts import (
    advance_context_generation,
    binding_readiness,
    record_binding_turn,
    record_delivery_turn,
)
from .terminal_policy import block_terminal_command

__all__ = [
    "REGISTERED_TOOLS",
    "TOOL_DEFINITIONS",
    "TOOLS",
    "ToolDefinition",
    "register",
    "tools",
]

TOOLS = handlers
tools = handlers

_SESSION_ENGAGEMENTS: dict[str, str] = {}
_EXECUTE_CODE_RECEIPTS: dict[str, tuple[str, str]] = {}
_EXECUTE_CODE_RECEIPTS_LOCK = threading.Lock()
_TARGET_TOOLS = {
    "violin_exec",
    "violin_exec_burst",
    "violin_httpx",
    "violin_nuclei",
    "violin_ffuf",
    "violin_listener",
}
_BROWSER_TARGET_TOOLS = {
    "browser_navigate",
    "browser_click",
    "browser_type",
    "browser_select",
    "browser_scroll",
}


@dataclass(frozen=True)
class ToolDefinition:
    """Single source of truth for one registered Hermes tool."""

    name: str
    model: type[BaseModel]
    schema: dict[str, Any]
    handler: Any
    emoji: str


TOOL_DEFINITIONS = (
    ToolDefinition(
        "violin_check_command",
        schemas.CheckCommandArgsModel,
        schemas.CHECK_COMMAND_SCHEMA,
        handlers.handle_check_command,
        "🛡️",
    ),
    ToolDefinition(
        "violin_record_ptt",
        schemas.RecordPttArgsModel,
        schemas.RECORD_PTT_SCHEMA,
        handlers.handle_record_ptt,
        "📝",
    ),
    ToolDefinition(
        "violin_record_hypothesis",
        schemas.RecordHypothesisArgsModel,
        schemas.RECORD_HYPOTHESIS_SCHEMA,
        handlers.handle_record_hypothesis,
        "🔎",
    ),
    ToolDefinition(
        "violin_exec", schemas.ExecArgsModel, schemas.EXEC_SCHEMA, handlers.handle_exec, "⚡"
    ),
    ToolDefinition(
        "violin_exec_status",
        schemas.ExecStatusArgsModel,
        schemas.EXEC_STATUS_SCHEMA,
        handlers.handle_exec_status,
        "i",
    ),
    ToolDefinition(
        "violin_exec_cancel",
        schemas.ExecCancelArgsModel,
        schemas.EXEC_CANCEL_SCHEMA,
        handlers.handle_exec_cancel,
        "x",
    ),
    ToolDefinition(
        "violin_review_batch",
        schemas.ReviewBatchArgsModel,
        schemas.REVIEW_BATCH_SCHEMA,
        handlers.handle_review_batch,
        "✅",
    ),
    ToolDefinition(
        "violin_rebind_pending_batch",
        schemas.RebindPendingBatchArgsModel,
        schemas.REBIND_PENDING_BATCH_SCHEMA,
        handlers.handle_rebind_pending_batch,
        "↔",
    ),
    ToolDefinition(
        "violin_heartbeat_done",
        schemas.HeartbeatDoneArgsModel,
        schemas.HEARTBEAT_DONE_SCHEMA,
        handlers.handle_heartbeat_done,
        "💓",
    ),
    ToolDefinition(
        "violin_exec_burst",
        schemas.ExecBurstArgsModel,
        schemas.EXEC_BURST_SCHEMA,
        handlers.handle_exec_burst,
        "🚀",
    ),
    ToolDefinition(
        "violin_target",
        schemas.TargetArgsModel,
        schemas.TARGET_SCHEMA,
        handlers.handle_target,
        "🎯",
    ),
    ToolDefinition(
        "violin_status",
        schemas.StatusArgsModel,
        schemas.STATUS_SCHEMA,
        handlers.handle_status,
        "📊",
    ),
    ToolDefinition(
        "violin_search_exploit",
        schemas.SearchExploitArgsModel,
        schemas.SEARCH_EXPLOIT_SCHEMA,
        handlers.handle_search_exploit,
        "?",
    ),
    ToolDefinition(
        "violin_httpx", schemas.HttpxArgsModel, schemas.HTTPX_SCHEMA, handlers.handle_httpx, "H"
    ),
    ToolDefinition(
        "violin_nuclei", schemas.NucleiArgsModel, schemas.NUCLEI_SCHEMA, handlers.handle_nuclei, "V"
    ),
    ToolDefinition(
        "violin_ffuf", schemas.FfufArgsModel, schemas.FFUF_SCHEMA, handlers.handle_ffuf, "F"
    ),
    ToolDefinition(
        "violin_listener",
        schemas.ListenerArgsModel,
        schemas.LISTENER_SCHEMA,
        handlers.handle_listener,
        "L",
    ),
)

REGISTERED_TOOLS = [definition.name for definition in TOOL_DEFINITIONS]


def _validated_handler(definition: ToolDefinition):
    """Validate the raw Hermes payload before entering a public handler."""

    def invoke(raw_args=None, **kwargs):
        try:
            validated = schemas.validate_args(definition.model, raw_args, strict=True)
            # Hypothesis writes are PATCH-like.  Preserve the caller's field
            # presence so omitted optional values do not become empty strings
            # that erase an existing canonical record.
            values = validated.model_dump(
                exclude_unset=definition.model is schemas.RecordHypothesisArgsModel
            )
        except ValidationError as exc:
            return json.dumps(
                {
                    "status": "invalid_arguments",
                    "errors": exc.errors(include_input=False, include_url=False),
                },
                ensure_ascii=False,
            )
        return definition.handler(values, **kwargs)

    invoke.__name__ = f"validated_{definition.handler.__name__}"
    return invoke


def register(ctx) -> None:
    """Called once by the plugin loader during discovery."""
    for definition in TOOL_DEFINITIONS:
        ctx.register_tool(
            name=definition.name,
            toolset="violin_guard",
            schema=definition.schema,
            handler=_validated_handler(definition),
            emoji=definition.emoji,
        )

    ctx.register_hook("pre_tool_call", _pre_tool_call_hook)
    ctx.register_hook("post_tool_call", _post_tool_call_hook)
    ctx.register_hook("pre_llm_call", _pre_llm_call_hook)
    ctx.register_hook("on_session_reset", _on_session_reset_hook)
    ctx.register_hook("on_session_finalize", _on_session_finalize_hook)


# ---------------------------------------------------------------------------
# Tool policy hooks
# ---------------------------------------------------------------------------


def _pre_tool_call_hook(tool_name=None, args=None, **kwargs):
    """Apply the raw-terminal classifier and the execute-code audit gate.

    Violin-specific execution tools carry the engagement context required for
    full scope/state validation.  The built-in terminal has no such fields, so
    it remains available only for host-local work; clearly target-touching
    commands must use ``violin_exec`` or ``violin_exec_burst``.
    """
    args = args if isinstance(args, dict) else {}
    session_id = str(kwargs.get("session_id") or args.get("session_id") or "")
    eng_dir = str(args.get("eng_dir") or "")
    if session_id and eng_dir:
        _SESSION_ENGAGEMENTS[session_id] = eng_dir
        state.record_session_id(eng_dir, session_id)
    if tool_name in _TARGET_TOOLS or tool_name in _BROWSER_TARGET_TOOLS:
        blocked = _check_turn_binding(tool_name, args, kwargs)
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


def _post_tool_call_hook(tool_name=None, args=None, result=None, duration_ms=0, **kwargs):
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
    if tool_name in {"web_search", "web_extract", "violin_search_exploit"}:
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


# ---------------------------------------------------------------------------
# Lifecycle hooks
# ---------------------------------------------------------------------------


def _pre_llm_call_hook(session_id=None, eng_dir=None, **kwargs):
    """Lifecycle heartbeat: tick the message counter before each LLM call."""
    if eng_dir:
        with contextlib.suppress(Exception):
            state.tick_message(str(eng_dir))
            state.record_session_id(str(eng_dir), session_id)
            if session_id:
                _SESSION_ENGAGEMENTS[str(session_id)] = str(eng_dir)
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


def _on_session_reset_hook(session_id=None, eng_dir=None, **kwargs) -> None:
    """Hook: session reset (context compression, /goal set, etc.)."""
    _abandon_execute_code_receipts(session_id, "session reset before tool completion")
    eng_dir = eng_dir or (_SESSION_ENGAGEMENTS.get(str(session_id)) if session_id else None)
    if eng_dir:
        with contextlib.suppress(Exception):
            state.tick_message(str(eng_dir))
            advance_context_generation(str(eng_dir), str(session_id or "reset"))


def _check_turn_binding(tool_name: str, args: dict, hook: dict) -> str | None:
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


def _on_session_finalize_hook(session_id=None, eng_dir=None, **kwargs) -> None:
    """Hook: session finalize.

    Closeout gates are explicit (violin_review_batch / close command). On finalize
    we leave a continuity marker so a fresh session can re-read pending state.
    """
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
