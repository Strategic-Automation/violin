"""Locked, receipt-backed skill delivery state."""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ...core.skills.skill_policy import validate_skill_selection
from .skill_receipt_store import (
    _context,
    _delivery_key,
    _is_sha256_digest,
    _load,
    _mutate,
    _now,
    _path,
    _preparing_expired,
    _preparing_expires_at,
    _prune,
    skill_content_digest,
)

__all__ = [
    "DeliveryReservation",
    "SkillViewResult",
    "advance_context_generation",
    "bind_task",
    "complete_delivery",
    "get_binding",
    "binding_readiness",
    "get_delivery",
    "record_binding_turn",
    "record_delivery_turn",
    "skill_content_digest",
    "prepare_delivery",
]


@dataclass(frozen=True)
class DeliveryReservation:
    id: str
    status: str
    skill: str
    content_digest: str
    session_id: str
    context_generation: int
    owner: bool
    owner_token: str = ""


@dataclass(frozen=True)
class SkillViewResult:
    ready: bool
    content: str = ""
    error: str = ""
    path: str = ""


def prepare_delivery(
    eng_dir: str | Path,
    *,
    session_id: str,
    skill: str,
    content_digest: str,
    phase: str,
    vulnerability_class: str | None = None,
    candidate_source: str | None = None,
) -> DeliveryReservation:
    """Reserve exactly one delivery for a semantic receipt key.

    Only the caller receiving ``owner=True`` may record the content returned by
    Hermes; concurrent callers see the same ``preparing`` receipt and do not
    deliver the content a second time.
    """

    if not session_id.strip() or not _is_sha256_digest(content_digest):
        raise ValueError("session_id and a complete sha256 content_digest are required")

    policy = validate_skill_selection(skill, phase, vulnerability_class, candidate_source)
    if policy.mismatch_reasons:
        raise ValueError("; ".join(policy.mismatch_reasons))

    def reserve(data: dict[str, Any]) -> DeliveryReservation:
        current_session, generation = _context(data, session_id.strip())
        identifier = _delivery_key(current_session, generation, skill, content_digest)
        existing = data["deliveries"].get(identifier)
        if existing and existing.get("status") == "delivered":
            return DeliveryReservation(
                identifier,
                existing["status"],
                skill,
                content_digest,
                current_session,
                generation,
                False,
            )
        if existing and existing.get("status") == "preparing" and not _preparing_expired(existing):
            return DeliveryReservation(
                identifier,
                existing["status"],
                skill,
                content_digest,
                current_session,
                generation,
                False,
            )
        owner_token = uuid.uuid4().hex
        now = _now()
        data["deliveries"][identifier] = {
            "id": identifier,
            "skill": skill,
            "content_digest": content_digest,
            "session_id": current_session,
            "context_generation": generation,
            "status": "preparing",
            "created_at": now,
            "updated_at": now,
            "expires_at": _preparing_expires_at(),
            "owner_token": owner_token,
            "attempts": int((existing or {}).get("attempts") or 0) + 1,
        }
        _prune(data)
        return DeliveryReservation(
            identifier,
            "preparing",
            skill,
            content_digest,
            current_session,
            generation,
            True,
            owner_token,
        )

    return _mutate(eng_dir, reserve)


def complete_delivery(
    eng_dir: str | Path,
    reservation: DeliveryReservation,
    result: SkillViewResult,
    *,
    delivered_turn_id: str | None = None,
) -> DeliveryReservation:
    """Complete a reservation after an actual Hermes ``skill_view`` call."""

    def complete(data: dict[str, Any]) -> DeliveryReservation:
        entry = data["deliveries"].get(reservation.id)
        if not entry or entry.get("status") != "preparing":
            raise ValueError("delivery reservation is no longer active")
        if not reservation.owner or not reservation.owner_token:
            raise ValueError("only the reservation owner may complete delivery")
        if entry.get("owner_token") != reservation.owner_token:
            raise ValueError("delivery reservation owner is stale; prepare a new delivery")
        content_digest = skill_content_digest(result.content) if result.ready else None
        if entry.get("content_digest") != reservation.content_digest:
            raise ValueError("delivery content digest does not match its reservation")
        if result.ready and content_digest != reservation.content_digest:
            raise ValueError("returned skill content does not match its reserved content digest")
        entry["status"] = "delivered" if result.ready else "failed"
        entry["updated_at"] = _now()
        entry["delivered_turn_id"] = delivered_turn_id if result.ready else None
        entry["content_digest"] = content_digest
        entry["error"] = result.error if not result.ready else None
        data["deliveries"][reservation.id] = entry
        return DeliveryReservation(
            reservation.id,
            entry["status"],
            reservation.skill,
            content_digest,
            reservation.session_id,
            reservation.context_generation,
            False,
        )

    return _mutate(eng_dir, complete)


def get_delivery(eng_dir: str | Path, delivery_id: str) -> dict[str, Any] | None:
    data, _ = _load(_path(eng_dir))
    return data["deliveries"].get(delivery_id)


def advance_context_generation(eng_dir: str | Path, session_id: str) -> int:
    """Invalidate active bindings after Hermes context reset/compression."""

    def advance(data: dict[str, Any]) -> int:
        _context(data, session_id.strip())
        data["context"]["generation"] = int(data["context"].get("generation") or 0) + 1
        return data["context"]["generation"]

    return _mutate(eng_dir, advance)


def bind_task(
    eng_dir: str | Path,
    *,
    task_id: str,
    delivery_id: str,
    hypothesis_id: str | None = None,
    technique: str = "",
) -> dict[str, Any]:
    """Bind a delivered receipt to one task/hypothesis for later enforcement."""

    def bind(data: dict[str, Any]) -> dict[str, Any]:
        delivery = data["deliveries"].get(delivery_id)
        if not delivery or delivery.get("status") != "delivered":
            raise ValueError("a delivered skill receipt is required before binding")
        binding = {
            "task_id": task_id,
            "delivery_id": delivery_id,
            "skill": delivery["skill"],
            "content_digest": delivery["content_digest"],
            "session_id": delivery["session_id"],
            "context_generation": delivery["context_generation"],
            "hypothesis_id": hypothesis_id or "",
            "technique": technique.strip(),
            "bound_at": _now(),
        }
        data["bindings"][task_id] = binding
        return binding

    return _mutate(eng_dir, bind)


def get_binding(eng_dir: str | Path, task_id: str) -> dict[str, Any] | None:
    data, _ = _load(_path(eng_dir))
    return data["bindings"].get(task_id)


def binding_readiness(
    eng_dir: str | Path, *, task_id: str, session_id: str
) -> tuple[dict[str, Any] | None, str | None]:
    """Return the active receipt binding, or a precise fail-closed reason."""

    data, recovered = _load(_path(eng_dir))
    if recovered:
        return None, "skill receipt state is unavailable; prepare the selected skill again"
    context = data.get("context") or {}
    binding = (data.get("bindings") or {}).get(task_id)
    if not binding:
        return None, "the active PTT task has no delivered skill binding"
    if str(context.get("session_id") or "") != session_id:
        return None, "the skill binding belongs to a different session"
    if int(binding.get("context_generation", -1)) != int(context.get("generation") or 0):
        return None, "the skill binding is stale after a context reset"
    delivery = (data.get("deliveries") or {}).get(binding.get("delivery_id"))
    if not delivery or delivery.get("status") != "delivered":
        return None, "the bound skill delivery is not ready"
    if delivery.get("content_digest") != binding.get("content_digest"):
        return None, "the bound skill content digest no longer matches its delivery"
    return {
        **binding,
        "delivered_turn_id": delivery.get("delivered_turn_id"),
        "delivered_api_request_id": delivery.get("delivered_api_request_id"),
    }, None


def record_delivery_turn(
    eng_dir: str | Path,
    *,
    delivery_id: str,
    turn_id: str,
    api_request_id: str = "",
) -> None:
    """Associate a successful ``skill_view`` result with its model call."""

    if not turn_id and not api_request_id:
        return

    def record(data: dict[str, Any]) -> None:
        entry = data["deliveries"].get(delivery_id)
        if entry and entry.get("status") == "delivered":
            entry["delivered_turn_id"] = turn_id
            entry["delivered_api_request_id"] = api_request_id
            entry["updated_at"] = _now()

    _mutate(eng_dir, record)


def record_binding_turn(
    eng_dir: str | Path,
    *,
    task_id: str,
    turn_id: str,
    api_request_id: str = "",
) -> None:
    """Associate a binding commit with its model call."""

    if not turn_id and not api_request_id:
        return

    def record(data: dict[str, Any]) -> None:
        binding = data["bindings"].get(task_id)
        if binding:
            binding["bound_turn_id"] = turn_id
            binding["bound_api_request_id"] = api_request_id
            binding["bound_at"] = _now()

    _mutate(eng_dir, record)
