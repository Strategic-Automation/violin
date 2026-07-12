"""Violin guard plugin — typed guard tools + forced check-command gate + doc-sync."""

from __future__ import annotations

import sys
from pathlib import Path

# Hermes loads profile plugins directly from ``<profile>/plugins`` and does not
# add the profile's ``scripts`` directory to Python's import path. Bootstrap the
# shared guard package before importing tool modules that depend on it.
_PROFILE_HOME = Path(__file__).resolve().parents[2]
_SCRIPTS_DIR = _PROFILE_HOME / "scripts"
if str(_SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS_DIR))

from . import schemas, tools  # noqa: E402 - profile scripts path is required first

_TOOLS = (
    ("violin_check_command", schemas.CHECK_COMMAND_SCHEMA, tools.handle_check_command, "🛡️"),
    ("violin_record_ptt", schemas.RECORD_PTT_SCHEMA, tools.handle_record_ptt, "📝"),
    (
        "violin_record_hypothesis",
        schemas.RECORD_HYPOTHESIS_SCHEMA,
        tools.handle_record_hypothesis,
        "🔎",
    ),
    ("violin_record_history", schemas.RECORD_HISTORY_SCHEMA, tools.handle_record_history, "🕓"),
    ("violin_exec", schemas.EXEC_SCHEMA, tools.handle_exec, "⚡"),
    ("violin_exec_status", schemas.EXEC_STATUS_SCHEMA, tools.handle_exec_status, "i"),
    ("violin_exec_cancel", schemas.EXEC_CANCEL_SCHEMA, tools.handle_exec_cancel, "x"),
    ("violin_sync_done", schemas.SYNC_DONE_SCHEMA, tools.handle_sync_done, "✅"),
    ("violin_heartbeat_done", schemas.HEARTBEAT_DONE_SCHEMA, tools.handle_heartbeat_done, "💓"),
    ("violin_message_tick", schemas.MESSAGE_TICK_SCHEMA, tools.handle_message_tick, "💬"),
    ("violin_exec_burst", schemas.EXEC_BURST_SCHEMA, tools.handle_exec_burst, "🚀"),
    ("violin_target", schemas.TARGET_SCHEMA, tools.handle_target, "🎯"),
    ("violin_status", schemas.STATUS_SCHEMA, tools.handle_status, "📊"),
    ("violin_search_exploit", schemas.SEARCH_EXPLOIT_SCHEMA, tools.handle_search_exploit, "?"),
    ("violin_nmap", schemas.NMAP_SCHEMA, tools.handle_nmap, "N"),
    ("violin_httpx", schemas.HTTPX_SCHEMA, tools.handle_httpx, "H"),
    ("violin_nuclei", schemas.NUCLEI_SCHEMA, tools.handle_nuclei, "V"),
    ("violin_ffuf", schemas.FFUF_SCHEMA, tools.handle_ffuf, "F"),
)


def register(ctx) -> None:
    for name, schema, handler, emoji in _TOOLS:
        ctx.register_tool(
            name=name, toolset="violin_guard", schema=schema, handler=handler, emoji=emoji
        )
