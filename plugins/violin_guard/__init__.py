"""Violin guard plugin — typed guard tools + forced check-command gate + doc-sync.

Hermes plugin registration entry point.
"""

from __future__ import annotations

import contextlib
from pathlib import Path

# Hermes loads profile plugins directly from ``<profile>/plugins`` and does not
# add the profile's ``scripts`` directory to Python's import path. Bootstrap the
# shared guard package before importing tool modules that depend on it.
_PROFILE_HOME = Path(__file__).resolve().parents[2]

from . import schemas, tools  # noqa: E402 - profile scripts path is required first

__all__ = ["register", "TOOLS", "REGISTERED_TOOLS"]

TOOLS = tools

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
    "violin_heartbeat_done",
    "violin_exec_burst",
    "violin_target",
    "violin_status",
    "violin_search_exploit",
    "violin_nmap",
    "violin_httpx",
    "violin_nuclei",
    "violin_ffuf",
]


def register(ctx) -> None:
    """Called once by the plugin loader during discovery."""
    # Register all 16 model-visible tools
    for name, schema, handler, emoji in (
        ("violin_check_command", schemas.CHECK_COMMAND_SCHEMA, tools.handle_check_command, "🛡️"),
        ("violin_record_ptt", schemas.RECORD_PTT_SCHEMA, tools.handle_record_ptt, "📝"),
        (
            "violin_record_hypothesis",
            schemas.RECORD_HYPOTHESIS_SCHEMA,
            tools.handle_record_hypothesis,
            "🔎",
        ),
        ("violin_exec", schemas.EXEC_SCHEMA, tools.handle_exec, "⚡"),
        ("violin_exec_status", schemas.EXEC_STATUS_SCHEMA, tools.handle_exec_status, "i"),
        ("violin_exec_cancel", schemas.EXEC_CANCEL_SCHEMA, tools.handle_exec_cancel, "x"),
        ("violin_sync_done", schemas.SYNC_DONE_SCHEMA, tools.handle_sync_done, "✅"),
        ("violin_heartbeat_done", schemas.HEARTBEAT_DONE_SCHEMA, tools.handle_heartbeat_done, "💓"),
        ("violin_exec_burst", schemas.EXEC_BURST_SCHEMA, tools.handle_exec_burst, "🚀"),
        ("violin_target", schemas.TARGET_SCHEMA, tools.handle_target, "🎯"),
        ("violin_status", schemas.STATUS_SCHEMA, tools.handle_status, "📊"),
        ("violin_search_exploit", schemas.SEARCH_EXPLOIT_SCHEMA, tools.handle_search_exploit, "?"),
        ("violin_nmap", schemas.NMAP_SCHEMA, tools.handle_nmap, "N"),
        ("violin_httpx", schemas.HTTPX_SCHEMA, tools.handle_httpx, "H"),
        ("violin_nuclei", schemas.NUCLEI_SCHEMA, tools.handle_nuclei, "V"),
        ("violin_ffuf", schemas.FFUF_SCHEMA, tools.handle_ffuf, "F"),
    ):
        ctx.register_tool(
            name=name,
            toolset="violin_guard",
            schema=schema,
            handler=handler,
            emoji=emoji,
        )

    # Lifecycle hooks
    ctx.register_hook("pre_llm_call", _pre_llm_call_hook)
    ctx.register_hook("on_session_reset", _on_session_reset_hook)
    ctx.register_hook("on_session_finalize", _on_session_finalize_hook)


# --------------------------------------------------------------------------- #
# Lifecycle hooks
# --------------------------------------------------------------------------- #


def _pre_llm_call_hook(session_id=None, eng_dir=None, **kwargs):
    """Lifecycle heartbeat: tick the message counter before each LLM call.

    This is the *supplementary* heartbeat — it advances the message cadence
    (used to surface periodic review locks) but never replaces the authoritative
    command gate. When ``eng_dir`` is available we record the tick; otherwise we
    simply return without mutating state.
    """
    from .core import state

    if eng_dir:
        with contextlib.suppress(Exception):
            state.tick_message(str(eng_dir))
    return None


def _on_session_reset_hook(session_id=None, eng_dir=None, **kwargs) -> None:
    """Hook: session reset (context compression, /goal set, etc.).

    Re-reads the engagement so message-count enforcement stays accurate across a
    context reset; the command-count gate remains authoritative for execution.
    """
    from .core import state

    if eng_dir:
        with contextlib.suppress(Exception):
            state.tick_message(str(eng_dir))


def _on_session_finalize_hook(session_id=None, eng_dir=None, **kwargs) -> None:
    """Hook: session finalize.

    Closeout gates are explicit (violin_sync_done / close command). On finalize
    we leave a continuity marker so a fresh session can re-read pending state.
    """
    from .core import state

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
