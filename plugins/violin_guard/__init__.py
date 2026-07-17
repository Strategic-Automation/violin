"""Violin guard plugin — typed guard tools + forced check-command gate + doc-sync.

Hermes plugin registration entry point.
"""

from __future__ import annotations

import contextlib

from . import (
    adapters,
    code_execution_audit,
    schemas,  # noqa: E402
    service,  # noqa: E402
    state,  # noqa: E402
)
from .terminal_policy import block_terminal_command

__all__ = ["register", "TOOLS", "REGISTERED_TOOLS", "tools"]

TOOLS = service
tools = service

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
    "violin_sync_done",
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
        ("violin_sync_done", schemas.SYNC_DONE_SCHEMA, service.handle_sync_done, "✅"),
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
    return None


def _on_session_reset_hook(session_id=None, eng_dir=None, **kwargs) -> None:
    """Hook: session reset (context compression, /goal set, etc.)."""
    if eng_dir:
        with contextlib.suppress(Exception):
            state.tick_message(str(eng_dir))


def _on_session_finalize_hook(session_id=None, eng_dir=None, **kwargs) -> None:
    """Hook: session finalize.

    Closeout gates are explicit (violin_sync_done / close command). On finalize
    we leave a continuity marker so a fresh session can re-read pending state.
    """
    if eng_dir:
        try:
            pending = state.has_pending_sync(str(eng_dir))
            if pending:
                state.set_heartbeat_pending(
                    str(eng_dir),
                    "session finalized with a pending sync lock; run violin_sync_done",
                )
        except Exception:
            pass
