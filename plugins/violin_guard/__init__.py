"""Violin guard plugin — typed guard tools + forced check-command gate + doc-sync.

Hermes plugin registration entry point.
"""

from __future__ import annotations

import os
from pathlib import Path
import sys

# Hermes loads profile plugins directly from ``<profile>/plugins`` and does not
# add the profile's ``scripts`` directory to Python's import path. Bootstrap the
# shared guard package before importing tool modules that depend on it.
_PROFILE_HOME = Path(__file__).resolve().parents[2]
from . import schemas, tools  # noqa: E402 - profile scripts path is required first

__all__ = ["register", "TOOLS"]

TOOLS = tools


def register(ctx) -> None:
    """Called once by the plugin loader during discovery."""
    # Register all 16 model-visible tools
    for name, schema, handler, emoji in (
        ("violin_check_command", schemas.CHECK_COMMAND_SCHEMA, tools.handle_check_command, "🛡️"),
        ("violin_record_ptt", schemas.RECORD_PTT_SCHEMA, tools.handle_record_ptt, "📝"),
        ("violin_record_hypothesis", schemas.RECORD_HYPOTHESIS_SCHEMA, tools.handle_record_hypothesis, "🔎"),
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


def _pre_llm_call_hook(session_id=None, **kwargs):
    """Supplementary lifecycle heartbeat; never replaces the command gate."""
    return None


def _on_session_reset_hook(**kwargs) -> None:
    """Hook: session reset (context compression, /goal set, etc.).

    No-op for message heartbeat; command-count enforcement remains authoritative.
    """
    pass


def _on_session_finalize_hook(**kwargs) -> None:
    """Hook: session finalize.

    No-op; closeout gates are explicit via violin_sync_done and close command.
    """
    pass
