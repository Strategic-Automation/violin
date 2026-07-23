"""Violin guard plugin — typed guard tools + forced check-command gate + doc-sync.

Hermes plugin registration entry point.
"""

from __future__ import annotations

import contextlib
import json
from pathlib import Path

from . import (
    code_execution_audit,
    ptt,
    schemas,  # noqa: E402
    service,  # noqa: E402
    state,  # noqa: E402
)
from .skill_receipts import (
    advance_context_generation,
    binding_readiness,
    record_binding_turn,
    record_delivery_turn,
)
from .terminal_policy import block_terminal_command

__all__ = ["register", "TOOLS", "REGISTERED_TOOLS", "tools"]

TOOLS = service
tools = service

_SESSION_ENGAGEMENTS: dict[str, str] = {}
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

# Tool names registered with the Hermes plugin loader. Kept in sync with the
# registration tuple below; the release gate compares these against
# plugin.yaml's provides_tools.
REGISTERED_TOOLS = [
    "violin_check_command",
    "violin_record_ptt",
    "violin_record_hypothesis",
    "violin_exec",
    "violin_exec_status",
    "violin_exec_cancel",
    "violin_review_batch",
    "violin_rebind_pending_batch",
    "violin_heartbeat_done",
    "violin_exec_burst",
    "violin_target",
    "violin_status",
    "violin_search_exploit",
    "violin_httpx",
    "violin_nuclei",
    "violin_ffuf",
    "violin_listener",
]


def register(ctx) -> None:
    """Called once by the plugin loader during discovery."""
    for name, schema, handler, emoji in (
        ("violin_check_command", schemas.CHECK_COMMAND_SCHEMA, service.handle_check_command, "🛡️"),
        ("violin_record_ptt", schemas.RECORD_PTT_SCHEMA, service.handle_record_ptt, "📝"),
        (
            "violin_record_hypothesis",
            schemas.RECORD_HYPOTHESIS_SCHEMA,
            service.handle_record_hypothesis,
            "🔎",
        ),
        ("violin_exec", schemas.EXEC_SCHEMA, service.handle_exec, "⚡"),
        ("violin_exec_status", schemas.EXEC_STATUS_SCHEMA, service.handle_exec_status, "i"),
        ("violin_exec_cancel", schemas.EXEC_CANCEL_SCHEMA, service.handle_exec_cancel, "x"),
        (
            "violin_review_batch",
            schemas.REVIEW_BATCH_SCHEMA,
            service.handle_review_batch,
            "✅",
        ),
        (
            "violin_rebind_pending_batch",
            schemas.REBIND_PENDING_BATCH_SCHEMA,
            service.handle_rebind_pending_batch,
            "↔",
        ),
        (
            "violin_heartbeat_done",
            schemas.HEARTBEAT_DONE_SCHEMA,
            service.handle_heartbeat_done,
            "💓",
        ),
        ("violin_exec_burst", schemas.EXEC_BURST_SCHEMA, service.handle_exec_burst, "🚀"),
        ("violin_target", schemas.TARGET_SCHEMA, service.handle_target, "🎯"),
        ("violin_status", schemas.STATUS_SCHEMA, service.handle_status, "📊"),
        (
            "violin_search_exploit",
            schemas.SEARCH_EXPLOIT_SCHEMA,
            service.handle_search_exploit,
            "?",
        ),
        ("violin_httpx", schemas.HTTPX_SCHEMA, service.handle_httpx, "H"),
        ("violin_nuclei", schemas.NUCLEI_SCHEMA, service.handle_nuclei, "V"),
        ("violin_ffuf", schemas.FFUF_SCHEMA, service.handle_ffuf, "F"),
        ("violin_listener", schemas.LISTENER_SCHEMA, service.handle_listener, "L"),
    ):
        ctx.register_tool(
            name=name,
            toolset="violin_guard",
            schema=schema,
            handler=handler,
            emoji=emoji,
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
        _metadata, message = code_execution_audit.validate_source(args.get("code"))
        return None if message is None else {"action": "block", "message": message}
    if tool_name != "terminal":
        return None
    message = block_terminal_command(args.get("command", ""))
    return None if message is None else {"action": "block", "message": message}


def _post_tool_call_hook(tool_name=None, args=None, result=None, duration_ms=0, **kwargs):
    """Write the auditable execute-code source receipt after dispatch."""
    if tool_name == "execute_code" and isinstance(args, dict):
        with contextlib.suppress(Exception):
            code_execution_audit.record_completion(args.get("code"), result, duration_ms)
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
    if not eng_dir or not turn_id:
        return
    try:
        payload = json.loads(result) if isinstance(result, str) else result
        if not isinstance(payload, dict):
            return
        skill = payload.get("skill") or {}
        delivery_id = str(skill.get("delivery_id") or "")
        if payload.get("status") == "skill_prepared" and delivery_id:
            record_delivery_turn(eng_dir, delivery_id=delivery_id, turn_id=turn_id)
        task_id = str(payload.get("task_id") or payload.get("binding_task_id") or "")
        if payload.get("status") == "ok" and task_id:
            record_binding_turn(eng_dir, task_id=task_id, turn_id=turn_id)
    except Exception:
        return


# ---------------------------------------------------------------------------
# Lifecycle hooks
# ---------------------------------------------------------------------------


def _pre_llm_call_hook(session_id=None, eng_dir=None, **kwargs):
    """Lifecycle heartbeat: tick the message counter before each LLM call.

    This is the *supplementary* heartbeat — it advances the message cadence
    (used to surface periodic review locks) but never replaces the authoritative
    command gate. When ``eng_dir`` is available we record the tick; otherwise we
    simply return without mutating state.
    """
    if eng_dir:
        with contextlib.suppress(Exception):
            state.tick_message(str(eng_dir))
            state.record_session_id(str(eng_dir), session_id)
            if session_id:
                _SESSION_ENGAGEMENTS[str(session_id)] = str(eng_dir)
    return None


def _on_session_reset_hook(session_id=None, eng_dir=None, **kwargs) -> None:
    """Hook: session reset (context compression, /goal set, etc.)."""
    eng_dir = eng_dir or _SESSION_ENGAGEMENTS.get(str(session_id or ""))
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
    turn_id = str(hook.get("turn_id") or "")
    if turn_id and turn_id in {
        str(binding.get("bound_turn_id") or ""),
        str((binding or {}).get("delivered_turn_id") or ""),
    }:
        return (
            "target activity is blocked in the skill delivery/binding turn; retry on the next turn"
        )
    return None


def _on_session_finalize_hook(session_id=None, eng_dir=None, **kwargs) -> None:
    """Hook: session finalize.

    Closeout gates are explicit (violin_review_batch / close command). On finalize
    we leave a continuity marker so a fresh session can re-read pending state.
    """
    if eng_dir:
        with contextlib.suppress(Exception):
            pending = state.has_pending_sync(str(eng_dir))
            if pending:
                state.set_heartbeat_pending(
                    str(eng_dir),
                    "session finalized with a pending sync lock; run violin_review_batch",
                )
