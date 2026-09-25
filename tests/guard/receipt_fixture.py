"""Test-only setup for receipt-authoritative target execution."""

from __future__ import annotations

import uuid
from pathlib import Path

from plugins.violin_guard.core.engagement import ptt, state
from plugins.violin_guard.core.skills.skill_receipts import (
    SkillViewResult,
    bind_task,
    complete_delivery,
    prepare_delivery,
)


def record_started_command(
    engagement: Path,
    command: str,
    phase: str = "RECON",
    task_id: str = "PT-010",
    *,
    reservation_id: str | None = None,
) -> tuple[int, bool, int, bool]:
    """Arm test review state through the runtime's execution accountant."""
    return state.commit_execution_start(
        engagement,
        command,
        phase,
        task_id,
        str(uuid.uuid4()),
        sync_reservation=reservation_id,
    )


def bind_active_task(
    engagement: Path,
    session_id: str = "test",
    *,
    skill: str = "pentest",
    hypothesis_id: str | None = None,
    vulnerability_class: str | None = None,
    candidate_source: str | None = None,
) -> None:
    state.record_session_id(engagement, session_id)
    active = ptt.find_active_task(ptt.parse_ptt(engagement / "state" / "ptt.md"))
    assert active is not None
    digest = "sha256:" + "a" * 64
    reserved = prepare_delivery(
        engagement,
        session_id=session_id,
        skill=skill,
        bundle_digest=digest,
        phase=active.phase,
        vulnerability_class=vulnerability_class,
        candidate_source=candidate_source,
    )
    if reserved.owner:
        reserved = complete_delivery(
            engagement, reserved, SkillViewResult(True, content="test skill")
        )
    bind_task(
        engagement,
        task_id=active.id,
        delivery_id=reserved.id,
        hypothesis_id=hypothesis_id,
        technique="test",
    )
