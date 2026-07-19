"""Locked, receipt-backed skill delivery state.

The module is deliberately latent in v3-02: callers may prepare and bind
deliveries, but existing execution guards do not consume the receipts until
the command-gate migration branch.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from . import state
from .skill_policy import validate_skill_selection

__all__ = [
    "DeliveryReservation",
    "HermesSkillViewAdapter",
    "SkillViewResult",
    "advance_context_generation",
    "bind_task",
    "complete_delivery",
    "get_binding",
    "binding_readiness",
    "get_delivery",
    "record_binding_turn",
    "record_delivery_turn",
    "prepare_delivery",
    "prepare_review_readiness",
]

_FILE_NAME = "skills.json"
_SCHEMA_VERSION = 1
_MAX_DELIVERIES = 200


def _now() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def _digest(value: str) -> str:
    return "sha256:" + hashlib.sha256(value.encode("utf-8")).hexdigest()


def _path(eng_dir: str | Path) -> Path:
    return state.resolve_eng_dir(eng_dir) / "state" / _FILE_NAME


def _empty(session_id: str = "", generation: int = 0) -> dict[str, Any]:
    return {
        "schema_version": _SCHEMA_VERSION,
        "context": {"session_id": session_id, "generation": generation},
        "deliveries": {},
        "bindings": {},
        "review_readiness": {},
    }


def _load(path: Path) -> tuple[dict[str, Any], bool]:
    """Load valid receipt state; recover malformed/old documents fail-closed."""

    if not path.exists():
        return _empty(), False
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return _empty(), True
    if not isinstance(raw, dict) or raw.get("schema_version") != _SCHEMA_VERSION:
        return _empty(), True
    if not isinstance(raw.get("context"), dict) or not isinstance(raw.get("deliveries"), dict):
        return _empty(), True
    raw.setdefault("bindings", {})
    raw.setdefault("review_readiness", {})
    return raw, False


def _mutate(eng_dir: str | Path, mutation: Callable[[dict[str, Any]], Any]) -> Any:
    path = _path(eng_dir)
    path.parent.mkdir(parents=True, exist_ok=True)
    with state.lock_file(path):
        data, recovered = _load(path)
        if recovered:
            data["recovered_at"] = _now()
        result = mutation(data)
        state.atomic_json(path, data)
        return result


def _context(data: dict[str, Any], session_id: str) -> tuple[str, int]:
    context = data.setdefault("context", {"session_id": "", "generation": 0})
    recorded = str(context.get("session_id") or "")
    if recorded and recorded != session_id:
        # A new Hermes session is a new context, never proof of the old load.
        context["session_id"] = session_id
        context["generation"] = int(context.get("generation") or 0) + 1
    elif not recorded:
        context["session_id"] = session_id
    return str(context["session_id"]), int(context.get("generation") or 0)


def _delivery_key(session_id: str, generation: int, skill: str, bundle_digest: str) -> str:
    return _digest(f"{session_id}\0{generation}\0{skill}\0{bundle_digest}")


def _prune(data: dict[str, Any]) -> None:
    deliveries = data["deliveries"]
    if len(deliveries) <= _MAX_DELIVERIES:
        return
    bound = {str(binding.get("delivery_id") or "") for binding in data["bindings"].values()}
    removable = sorted(
        (entry for entry in deliveries.values() if entry.get("id") not in bound),
        key=lambda entry: str(entry.get("updated_at") or ""),
    )
    for entry in removable[: max(0, len(deliveries) - _MAX_DELIVERIES)]:
        deliveries.pop(entry["id"], None)


@dataclass(frozen=True)
class DeliveryReservation:
    id: str
    status: str
    skill: str
    bundle_digest: str
    session_id: str
    context_generation: int
    owner: bool
    recovered_state: bool = False


@dataclass(frozen=True)
class SkillViewResult:
    ready: bool
    content: str = ""
    error: str = ""
    path: str = ""


class HermesSkillViewAdapter:
    """Small adapter around Hermes's JSON-returning ``skill_view`` helper."""

    def __init__(self, view: Callable[..., str] | None = None):
        self._view = view

    def view(self, skill: str, task_id: str | None = None) -> SkillViewResult:
        try:
            view = self._view
            if view is None:
                from tools.skills_tool import skill_view as view  # type: ignore[import-not-found]
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


def prepare_delivery(
    eng_dir: str | Path,
    *,
    session_id: str,
    skill: str,
    bundle_digest: str,
    phase: str,
    vulnerability_class: str | None = None,
    candidate_source: str | None = None,
) -> DeliveryReservation:
    """Reserve exactly one delivery for a semantic receipt key.

    Only the caller receiving ``owner=True`` may invoke Hermes and then call
    :func:`complete_delivery`; concurrent callers see the same ``preparing``
    receipt and never receive duplicate skill content.
    """

    if not session_id.strip() or not bundle_digest.startswith("sha256:"):
        raise ValueError("session_id and a sha256 bundle_digest are required")
    policy = validate_skill_selection(skill, phase, vulnerability_class, candidate_source)
    if policy.mismatch_reasons:
        raise ValueError("; ".join(policy.mismatch_reasons))

    def reserve(data: dict[str, Any]) -> DeliveryReservation:
        current_session, generation = _context(data, session_id.strip())
        identifier = _delivery_key(current_session, generation, skill, bundle_digest)
        existing = data["deliveries"].get(identifier)
        if existing and existing.get("status") in {"preparing", "delivered"}:
            return DeliveryReservation(
                identifier,
                existing["status"],
                skill,
                bundle_digest,
                current_session,
                generation,
                False,
            )
        data["deliveries"][identifier] = {
            "id": identifier,
            "skill": skill,
            "bundle_digest": bundle_digest,
            "session_id": current_session,
            "context_generation": generation,
            "status": "preparing",
            "created_at": _now(),
            "updated_at": _now(),
            "attempts": int((existing or {}).get("attempts") or 0) + 1,
        }
        _prune(data)
        return DeliveryReservation(
            identifier, "preparing", skill, bundle_digest, current_session, generation, True
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
        entry["status"] = "delivered" if result.ready else "failed"
        entry["updated_at"] = _now()
        entry["delivered_turn_id"] = delivered_turn_id if result.ready else None
        entry["content_digest"] = _digest(result.content) if result.ready else None
        entry["error"] = result.error if not result.ready else None
        data["deliveries"][reservation.id] = entry
        return DeliveryReservation(
            reservation.id,
            entry["status"],
            reservation.skill,
            reservation.bundle_digest,
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
            "bundle_digest": delivery["bundle_digest"],
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
    if delivery.get("bundle_digest") != binding.get("bundle_digest"):
        return None, "the bound skill digest no longer matches its delivery"
    return {**binding, "delivered_turn_id": delivery.get("delivered_turn_id")}, None


def record_delivery_turn(eng_dir: str | Path, *, delivery_id: str, turn_id: str) -> None:
    """Associate a successful ``skill_view`` result with its Hermes turn."""

    if not turn_id:
        return

    def record(data: dict[str, Any]) -> None:
        entry = data["deliveries"].get(delivery_id)
        if entry and entry.get("status") == "delivered":
            entry["delivered_turn_id"] = turn_id
            entry["updated_at"] = _now()

    _mutate(eng_dir, record)


def record_binding_turn(eng_dir: str | Path, *, task_id: str, turn_id: str) -> None:
    """Associate a binding commit with its Hermes turn."""

    if not turn_id:
        return

    def record(data: dict[str, Any]) -> None:
        binding = data["bindings"].get(task_id)
        if binding:
            binding["bound_turn_id"] = turn_id
            binding["bound_at"] = _now()

    _mutate(eng_dir, record)


def prepare_review_readiness(
    eng_dir: str | Path,
    *,
    finding_id: str,
    evidence_digest: str,
    delivery_id: str,
) -> dict[str, Any]:
    """Record a per-evidence-set review readiness receipt for later fp-check gating."""

    def prepare(data: dict[str, Any]) -> dict[str, Any]:
        delivery = data["deliveries"].get(delivery_id)
        if (
            not delivery
            or delivery.get("status") != "delivered"
            or delivery.get("skill") != "fp-check"
        ):
            raise ValueError("a delivered fp-check receipt is required for review readiness")
        receipt = {
            "finding_id": finding_id,
            "evidence_digest": evidence_digest,
            "delivery_id": delivery_id,
            "prepared_at": _now(),
        }
        data["review_readiness"][f"{finding_id}:{evidence_digest}"] = receipt
        return receipt

    return _mutate(eng_dir, prepare)
