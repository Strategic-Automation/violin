"""Subpackage exporting all modular tool handler functions and internal helpers."""

from __future__ import annotations

from ..core.skill_receipts import HermesSkillViewAdapter
from .base import (
    _call,
    _check_command_internal,
    _eng_path,
    _json,
    _result,
    _running_background_command,
    _serialize_errors,
)
from .exec_handlers import (
    handle_exec,
    handle_exec_burst,
    handle_exec_cancel,
    handle_exec_status,
    handle_heartbeat_done,
)
from .hypothesis_handlers import _scope_hosts, handle_record_hypothesis
from .ptt_handlers import (
    _rebind_fields,
    _start_ptt_task,
    _task_row_contains,
    _validate_pending_history,
    _validate_pending_identity,
    _validate_review_batch,
    _validated_replacement_task,
    _with_skill_token,
    handle_rebind_pending_batch,
    handle_record_ptt,
    handle_review_batch,
)
from .target_handlers import handle_status, handle_target

__all__ = [
    "HermesSkillViewAdapter",
    "_call",
    "_check_command_internal",
    "_eng_path",
    "_json",
    "_rebind_fields",
    "_result",
    "_running_background_command",
    "_scope_hosts",
    "_serialize_errors",
    "_start_ptt_task",
    "_task_row_contains",
    "_validate_pending_history",
    "_validate_pending_identity",
    "_validate_review_batch",
    "_validated_replacement_task",
    "_with_skill_token",
    "handle_exec",
    "handle_exec_burst",
    "handle_exec_cancel",
    "handle_exec_status",
    "handle_heartbeat_done",
    "handle_rebind_pending_batch",
    "handle_record_hypothesis",
    "handle_record_ptt",
    "handle_review_batch",
    "handle_status",
    "handle_target",
]
