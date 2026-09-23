"""Versioned executor state for Violin 4.0 engagements."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError


class RuntimeStateError(ValueError):
    """Persisted executor state is malformed or unsupported for this release."""


class _StateModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class Reservation(_StateModel):
    phase: str
    remaining: int = Field(ge=1)
    created_at: str


class ExecutionAccount(_StateModel):
    command: str
    phase: str
    reserved: bool
    accounted_at: str


class PendingCommand(_StateModel):
    command: str
    phase: str
    execution_id: str | None = None


class PendingBatch(_StateModel):
    batch_id: str
    commands: list[PendingCommand]
    phase: str
    created_at: str
    ptt_task_id: str
    ptt_reviewed: bool = False
    credit_limit: int = Field(ge=0)
    ptt_note: str | None = None
    ptt_reviewed_at: str | None = None


class RebindAuditEntry(_StateModel):
    timestamp: str
    batch_id: str
    old_task_id: str
    new_task_id: str
    note: str


class HeartbeatState(_StateModel):
    pending: bool = False
    reason: str | None = None
    created_at: str | None = None


class LastCheck(_StateModel):
    command: str
    phase: str
    at: str
    execution_id: str | None = None


class CountsState(_StateModel):
    commands: int = Field(default=0, ge=0)
    messages: int = Field(default=0, ge=0)
    last_check: LastCheck | None = None
    execution_ids: list[str] = Field(default_factory=list)


class SyncState(_StateModel):
    credit: int | None = Field(default=None, ge=0)
    reservations: dict[str, Reservation] = Field(default_factory=dict)
    pending: PendingBatch | None = None
    rebind_audit: list[RebindAuditEntry] = Field(default_factory=list)
    execution_accounts: dict[str, ExecutionAccount] = Field(default_factory=dict)


class RuntimeState(_StateModel):
    schema_version: Literal[1] = 1
    sync: SyncState = Field(default_factory=SyncState)
    counts: CountsState = Field(default_factory=CountsState)
    heartbeat: HeartbeatState = Field(default_factory=HeartbeatState)


_LEGACY_FILES = ("sync.json", "counts.json", "heartbeat.json")


def load_runtime_state(path: Path) -> RuntimeState:
    """Load v4 state, reject legacy state, or return clean-engagement defaults."""
    legacy = [name for name in _LEGACY_FILES if (path.parent / name).exists()]
    if legacy:
        names = ", ".join(legacy)
        raise RuntimeStateError(
            f"Violin 3.3 state ({names}) cannot be used by Violin 4.0; "
            "reinitialize the engagement or start a new engagement before continuing"
        )

    if path.exists():
        try:
            return RuntimeState.model_validate_json(path.read_text(encoding="utf-8"), strict=True)
        except (OSError, json.JSONDecodeError, ValidationError) as exc:
            raise RuntimeStateError(f"runtime state is malformed or unsupported: {exc}") from exc
    return RuntimeState()


def timestamp() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")
