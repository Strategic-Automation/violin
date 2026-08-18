"""Pending batch rebinding handlers and validation."""

from __future__ import annotations

from typing import Any

from ..core import ptt, state
from ..core.history import history_contains
from .base import (
    _eng_path,
    _json,
    _serialize_errors,
)


def _rebind_fields(args: dict[str, Any]) -> tuple[str, str, str, str, str]:
    if args.get("confirm") is not True:
        raise ValueError("explicit confirm=true is required to rebind a pending batch")
    values = tuple(
        str(args.get(key) or "").strip()
        for key in ("eng_dir", "batch_id", "current_task_id", "replacement_task_id", "note")
    )
    if not all(values):
        raise ValueError(
            "eng_dir, batch_id, current_task_id, replacement_task_id, and note are required"
        )
    return values


def _validate_pending_identity(
    pending: dict[str, Any], batch_id: str, current_task_id: str
) -> None:
    actual_batch_id = str(pending.get("batch_id") or "")
    if actual_batch_id != batch_id:
        raise ValueError(
            f"stale batch id {batch_id!r}; current pending batch is {actual_batch_id!r}"
        )
    captured_task_id = str(pending.get("ptt_task_id") or "")
    if captured_task_id != current_task_id:
        raise ValueError(
            f"current task {current_task_id!r} does not match batch task {captured_task_id!r}"
        )


def _validate_pending_history(eng_dir: str, pending: dict[str, Any]) -> None:
    missing = next(
        (
            str(item.get("command") or "")
            for item in pending.get("commands") or []
            if item.get("command") and not history_contains(eng_dir, str(item.get("command")))
        ),
        "",
    )
    if missing:
        raise ValueError(
            f"pending command not yet in exact history: {missing!r}; "
            "wait for the batch to finish before rebinding"
        )


def _validated_replacement_task(
    eng_dir: str,
    pending: dict[str, Any],
    current_task_id: str,
    replacement_task_id: str,
) -> ptt.PttTask:
    tasks = ptt.parse_ptt(_eng_path(eng_dir) / "state" / "ptt.md")
    if ptt.validate_ptt(tasks).errors:
        raise ValueError("PTT must have exactly one valid active task before rebinding")
    by_id = {task.id: task for task in tasks}
    if current_task_id not in by_id:
        raise ValueError(f"current batch task {current_task_id!r} is missing from the PTT")
    replacement = by_id.get(replacement_task_id)
    if replacement is None:
        raise ValueError(f"replacement task {replacement_task_id!r} is missing from the PTT")
    active = ptt.find_active_task(tasks)
    if active is None or active.id != replacement_task_id:
        raise ValueError(
            f"replacement task {replacement_task_id!r} must be the sole active [~] task"
        )
    phases = {
        str(item.get("phase") or pending.get("phase") or "")
        for item in pending.get("commands") or []
    } - {""}
    incompatible = sorted(
        phase for phase in phases if not ptt.task_matches_phase(replacement, phase)
    )
    if incompatible:
        raise ValueError(
            f"replacement task {replacement_task_id!r} is not phase-compatible with "
            + ", ".join(incompatible)
        )
    return replacement


@_serialize_errors
def handle_rebind_pending_batch(args: dict[str, Any], **kwargs: Any) -> str:
    """Explicitly move a completed pending batch to another active PTT task."""
    try:
        eng_dir, batch_id, current_task_id, replacement_task_id, note = _rebind_fields(args)
        pending = state.get_pending_sync(eng_dir)
        if not pending:
            raise ValueError("no pending execution batch")
        _validate_pending_identity(pending, batch_id, current_task_id)
        _validate_pending_history(eng_dir, pending)
        _validated_replacement_task(eng_dir, pending, current_task_id, replacement_task_id)
        audit = state.rebind_pending_sync(
            eng_dir,
            expected_batch_id=batch_id,
            current_task_id=current_task_id,
            replacement_task_id=replacement_task_id,
            note=note,
        )
        return _json(
            "ok",
            batch_id=batch_id,
            ptt_task_id=replacement_task_id,
            ptt_reviewed=False,
            audit=audit,
        )
    except Exception as exc:
        return _json("error", error=str(exc))


__all__ = [
    "_rebind_fields",
    "_validate_pending_history",
    "_validate_pending_identity",
    "_validated_replacement_task",
    "handle_rebind_pending_batch",
]
