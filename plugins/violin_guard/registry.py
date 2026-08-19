"""Hermes tool definitions, argument validators, and plugin discovery registry."""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from pydantic import BaseModel, ValidationError

from . import handlers
from .core import schemas
from .hooks import (
    _on_session_finalize_hook,
    _on_session_reset_hook,
    _post_tool_call_hook,
    _pre_llm_call_hook,
    _pre_tool_call_hook,
)


@dataclass(frozen=True)
class ToolDefinition:
    """Single source of truth for one registered Hermes tool."""

    name: str
    model: type[BaseModel]
    schema: dict[str, Any]
    handler: Callable[..., str]
    emoji: str


TOOL_DEFINITIONS = (
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
)

REGISTERED_TOOLS = [definition.name for definition in TOOL_DEFINITIONS]


def _validated_handler(definition: ToolDefinition) -> Callable[..., str]:
    """Validate the raw Hermes payload before entering a public handler."""

    def invoke(raw_args: Any = None, **kwargs: Any) -> str:
        try:
            validated = schemas.validate_args(definition.model, raw_args, strict=True)
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


def register(ctx: Any) -> None:
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


__all__ = [
    "REGISTERED_TOOLS",
    "TOOL_DEFINITIONS",
    "ToolDefinition",
    "_validated_handler",
    "register",
]
