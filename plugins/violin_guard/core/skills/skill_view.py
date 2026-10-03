"""Hermes skill-view adapter and its per-session read reservation."""

from __future__ import annotations

import json
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ...core.skills.skill_policy import validate_skill_selection
from .skill_receipt_store import (
    _context,
    _digest,
    _mutate,
    _now,
    _preparing_expired,
    _preparing_expires_at,
)
from .skill_receipts import SkillViewResult

try:
    from tools.skills_tool import skill_view as _hermes_skill_view  # type: ignore[import-not-found]
except ImportError:
    _hermes_skill_view = None

__all__ = [
    "HermesSkillViewAdapter",
    "SkillViewReservation",
    "finish_skill_view",
    "reserve_skill_view",
]


@dataclass(frozen=True)
class SkillViewReservation:
    id: str
    session_id: str
    context_generation: int
    skill: str
    owner: bool
    status: str
    owner_token: str = ""
    delivery_id: str = ""
    content_digest: str = ""


class HermesSkillViewAdapter:
    """Small adapter around Hermes's JSON-returning ``skill_view`` helper."""

    def __init__(self, view: Callable[..., str] | None = None):
        self._view = view

    def view(self, skill: str, task_id: str | None = None) -> SkillViewResult:
        try:
            view = self._view or _hermes_skill_view
            if view is None:
                return SkillViewResult(
                    False, error="skill_view unavailable: tools.skills_tool not found"
                )
            raw = view(skill, task_id=task_id)
            payload = json.loads(raw) if isinstance(raw, str) else raw
            if not isinstance(payload, dict) or not payload.get("success"):
                return SkillViewResult(
                    False, error=str((payload or {}).get("error") or "skill_view failed")
                )
            content = str(payload.get("content") or "")
            if not content:
                return SkillViewResult(False, error="skill_view returned no skill content")
            return SkillViewResult(True, content=content, path=str(payload.get("path") or ""))
        except Exception as exc:  # Hermes availability is an external dependency.
            return SkillViewResult(False, error=f"skill_view unavailable: {exc}")


def _skill_view_key(session_id: str, generation: int, skill: str) -> str:
    return _digest(f"{session_id}\0{generation}\0{skill}")


def reserve_skill_view(
    eng_dir: str | Path,
    *,
    session_id: str,
    skill: str,
    phase: str,
    vulnerability_class: str | None = None,
    candidate_source: str | None = None,
) -> SkillViewReservation:
    """Reserve one Hermes read; reuse only a content-addressed receipt for this context."""
    if not session_id.strip():
        raise ValueError("session_id is required")
    policy = validate_skill_selection(skill, phase, vulnerability_class, candidate_source)
    if policy.mismatch_reasons:
        raise ValueError("; ".join(policy.mismatch_reasons))

    def reserve(data: dict[str, Any]) -> SkillViewReservation:
        current_session, generation = _context(data, session_id.strip())
        key = _skill_view_key(current_session, generation, skill)
        existing = data["view_reservations"].get(key)
        if existing and not _preparing_expired(existing):
            return SkillViewReservation(key, current_session, generation, skill, False, "preparing")
        owner_token = uuid.uuid4().hex
        now = _now()
        data["view_reservations"][key] = {
            "status": "preparing",
            "session_id": current_session,
            "context_generation": generation,
            "skill": skill,
            "created_at": now,
            "updated_at": now,
            "expires_at": _preparing_expires_at(),
            "owner_token": owner_token,
        }
        return SkillViewReservation(
            key, current_session, generation, skill, True, "preparing", owner_token
        )

    return _mutate(eng_dir, reserve)


def finish_skill_view(
    eng_dir: str | Path,
    reservation: SkillViewReservation,
) -> None:
    """Release the exclusive slot after this request's Hermes view attempt."""

    def finish(data: dict[str, Any]) -> None:
        if not reservation.owner or not reservation.owner_token:
            raise ValueError("only the skill view reservation owner may finish it")
        entry = data["view_reservations"].get(reservation.id)
        if not entry or entry.get("owner_token") != reservation.owner_token:
            raise ValueError("skill view reservation owner is stale")
        data["view_reservations"].pop(reservation.id, None)

    _mutate(eng_dir, finish)
