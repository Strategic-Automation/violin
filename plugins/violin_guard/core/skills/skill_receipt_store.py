"""Locked JSON storage helpers for skill delivery receipts."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from ...core.engagement import state

_FILE_NAME = "skills.json"
_SCHEMA_VERSION = 3
_MAX_DELIVERIES = 200
_PREPARING_TTL_SECONDS = 300


def _now() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def _digest(value: str) -> str:
    return "sha256:" + hashlib.sha256(value.encode("utf-8")).hexdigest()


def skill_content_digest(content: str) -> str:
    """Return the SHA-256 digest of the exact UTF-8 skill text returned by Hermes."""

    return _digest(content)


def _is_sha256_digest(value: str | None) -> bool:
    if not isinstance(value, str) or len(value) != 71 or not value.startswith("sha256:"):
        return False
    return all(character in "0123456789abcdef" for character in value[7:])


def _preparing_expired(entry: dict[str, Any]) -> bool:
    value = str(entry.get("expires_at") or "").strip()
    if value:
        try:
            return datetime.fromisoformat(value.replace("Z", "+00:00")) <= datetime.now(UTC)
        except ValueError:
            return True
    updated = str(entry.get("updated_at") or entry.get("created_at") or "").strip()
    if not updated:
        return True
    try:
        started = datetime.fromisoformat(updated.replace("Z", "+00:00"))
    except ValueError:
        return True
    return (datetime.now(UTC) - started).total_seconds() >= _PREPARING_TTL_SECONDS


def _preparing_expires_at() -> str:
    return (
        (datetime.now(UTC) + timedelta(seconds=_PREPARING_TTL_SECONDS))
        .isoformat()
        .replace("+00:00", "Z")
    )


def _path(eng_dir: str | Path) -> Path:
    return state.resolve_eng_dir(eng_dir) / "state" / _FILE_NAME


def _empty(session_id: str = "", generation: int = 0) -> dict[str, Any]:
    return {
        "schema_version": _SCHEMA_VERSION,
        "context": {"session_id": session_id, "generation": generation},
        "deliveries": {},
        "bindings": {},
        "view_reservations": {},
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
    raw.setdefault("view_reservations", {})
    return raw, False


def _mutate(eng_dir: str | Path, mutation: Callable[[dict[str, Any]], Any]) -> Any:
    path = _path(eng_dir)
    state.ensure_dir(path.parent)
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


def _delivery_key(session_id: str, generation: int, skill: str, content_digest: str) -> str:
    return _digest(f"{session_id}\0{generation}\0{skill}\0{content_digest}")


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
