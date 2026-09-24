"""Phase compatibility shared by pending-batch review and rebinding."""

from __future__ import annotations

from typing import Any

from ..core.engagement import ptt


def validate_pending_phases(task: ptt.PttTask, pending: dict[str, Any], *, task_label: str) -> None:
    """Reject incompatible command phases with the caller's existing task label."""
    phases = {
        str(item.get("phase") or pending.get("phase") or "")
        for item in pending.get("commands") or []
    } - {""}
    incompatible = sorted(phase for phase in phases if not ptt.task_matches_phase(task, phase))
    if incompatible:
        raise ValueError(
            f"{task_label} {task.id!r} is not phase-compatible with " + ", ".join(incompatible)
        )
