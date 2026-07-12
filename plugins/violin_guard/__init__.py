"""Violin guard plugin — typed guard tools + forced check-command gate + doc-sync."""
from . import schemas, tools

_TOOLS = (
    ("violin_check_command",     schemas.CHECK_COMMAND_SCHEMA,     tools.handle_check_command,     "🛡️"),
    ("violin_record_ptt",        schemas.RECORD_PTT_SCHEMA,        tools.handle_record_ptt,        "📝"),
    ("violin_record_hypothesis", schemas.RECORD_HYPOTHESIS_SCHEMA, tools.handle_record_hypothesis, "🔎"),
    ("violin_record_history",    schemas.RECORD_HISTORY_SCHEMA,    tools.handle_record_history,    "🕓"),
    ("violin_exec",              schemas.EXEC_SCHEMA,              tools.handle_exec,              "⚡"),
    ("violin_sync_done",         schemas.SYNC_DONE_SCHEMA,         tools.handle_sync_done,         "✅"),
    ("violin_heartbeat_done",    schemas.HEARTBEAT_DONE_SCHEMA,    tools.handle_heartbeat_done,    "💓"),
    ("violin_message_tick",      schemas.MESSAGE_TICK_SCHEMA,      tools.handle_message_tick,      "💬"),
)


def register(ctx) -> None:
    for name, schema, handler, emoji in _TOOLS:
        ctx.register_tool(name=name, toolset="violin_guard",
                          schema=schema, handler=handler, emoji=emoji)
