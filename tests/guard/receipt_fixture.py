"""Test-only setup for receipt-authoritative target execution."""

from __future__ import annotations

from pathlib import Path

from plugins.violin_guard import ptt, state
from plugins.violin_guard.skill_receipts import (
    SkillViewResult,
    bind_task,
    complete_delivery,
    prepare_delivery,
)


def bind_active_task(engagement: Path, session_id: str = "test") -> None:
    state.record_session_id(engagement, session_id)
    active = ptt.find_active_task(ptt.parse_ptt(engagement / "state" / "ptt.md"))
    assert active is not None
    digest = "sha256:" + "a" * 64
    reserved = prepare_delivery(
        engagement, session_id=session_id, skill="pentest", bundle_digest=digest, phase=active.phase
    )
    if reserved.owner:
        reserved = complete_delivery(
            engagement, reserved, SkillViewResult(True, content="test skill")
        )
    bind_task(engagement, task_id=active.id, delivery_id=reserved.id, technique="test")
