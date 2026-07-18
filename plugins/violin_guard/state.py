"""State machine, advisory file locking, and JSON storage."""

from __future__ import annotations

import json
import os
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from filelock import FileLock

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

DEFAULT_SYNC_CREDIT = 5
COMMAND_INTERVAL = 50
MAX_BURST_COMMANDS = 20
PHASE_SYNC_CREDIT = {
    "RECON": 10,
    "VULN_RESEARCH": 10,
    "EXPLOITATION": 20,
    "POST_EXPLOITATION": 20,
    "PRIVESC": 20,
    "FLAGS": 20,
}

# Local tools
LOCAL_TOOLS = {"echo", "true", "false", "printf", "pwd", "ls", "cat", "date"}

_STATE_DIR = "state"
_SYNC_FILE = "sync.json"
_HEARTBEAT_FILE = "heartbeat.json"
_COUNTS_FILE = "counts.json"
_SESSION_FILE = "session.json"


# ---------------------------------------------------------------------------
# Path helpers
# ---------------------------------------------------------------------------


def _eng_root() -> Path:
    """Return Violin's stable profile/repository root for relative paths."""
    override = os.environ.get("VIOLIN_ENG_ROOT", "").strip()
    if override:
        return Path(override).expanduser().resolve()
    # <profile>/plugins/violin_guard/state.py -> <profile>
    return Path(__file__).resolve().parents[2]


def resolve_eng_dir(eng_dir: str | Path) -> Path:
    """Resolve an engagement directory path (absolute or relative to profile root)."""
    path = Path(eng_dir).expanduser()
    if not path.is_absolute():
        path = _eng_root() / path
    return path.resolve()


def resolve_session_id(eng_dir: str | Path, session_id: str | None = None) -> str:
    """Return an explicit session id or the engagement's recorded session.

    Tool calls should not fail merely because the runtime omitted a value it
    already supplied to the lifecycle hook.  Older engagements are supported
    by inferring the id when they contain exactly one skill-load marker.
    """
    if session_id and session_id.strip():
        return session_id.strip()
    root = resolve_eng_dir(eng_dir)
    recorded = str(read_json(root / _STATE_DIR / _SESSION_FILE).get("session_id") or "").strip()
    if recorded:
        return recorded
    markers = (
        list((root / _STATE_DIR).glob(".skill-loaded-*")) if (root / _STATE_DIR).exists() else []
    )
    return markers[0].name.removeprefix(".skill-loaded-") if len(markers) == 1 else ""


def record_session_id(eng_dir: str | Path, session_id: str | None) -> None:
    if session_id and session_id.strip():
        atomic_json(_state_dir(eng_dir) / _SESSION_FILE, {"session_id": session_id.strip()})


def _state_dir(eng_dir: str | Path) -> Path:
    p = resolve_eng_dir(eng_dir) / _STATE_DIR
    p.mkdir(parents=True, exist_ok=True)
    return p


# ---------------------------------------------------------------------------
# Storage primitives
# ---------------------------------------------------------------------------


@contextmanager
def lock_file(path: Path):
    """Acquire an exclusive advisory lock on ``path`` for the duration of a ``with`` block."""
    lock_path = path.with_suffix(path.suffix + ".lock")
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    with FileLock(str(lock_path), timeout=20):
        yield


def read_json(path: Path) -> dict[str, Any]:
    """Read a JSON document, returning an empty dict on error."""
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}


def atomic_json(path: Path, data: dict[str, Any]) -> None:
    """Write JSON atomically by replacing a temporary swap file."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")
    tmp.replace(path)


def mutate_json(path: Path, mutation) -> Any:
    """Apply ``mutation`` to one state document under a single file lock."""
    with lock_file(path):
        data = read_json(path)
        result = mutation(data)
        atomic_json(path, data)
        return result


# ---------------------------------------------------------------------------
# Local command classification
# ---------------------------------------------------------------------------


def is_local_bookkeeping_command(command: str) -> bool:
    """Whether a command is a harmless local bookkeeping action."""
    leading = command.strip().split(maxsplit=1)
    return bool(leading) and leading[0] in LOCAL_TOOLS


# ---------------------------------------------------------------------------
# Sync credit / pending sync
# ---------------------------------------------------------------------------


def _sync_path(eng_dir: str | Path) -> Path:
    return _state_dir(eng_dir) / _SYNC_FILE


def sync_credit_limit(phase: str | None = None) -> int:
    key = str(phase or "").strip().upper().replace("-", "_")
    return PHASE_SYNC_CREDIT.get(key, DEFAULT_SYNC_CREDIT)


def sync_credit_remaining(eng_dir: str | Path, phase: str | None = None) -> int:
    data = read_json(_sync_path(eng_dir))
    return max(0, data.get("credit", sync_credit_limit(phase)))


def spend_sync_credit(eng_dir: str | Path, phase: str) -> int:
    path = _sync_path(eng_dir)

    def spend(data: dict[str, Any]) -> int:
        starting_credit = data.get("credit", sync_credit_limit(phase))
        credit = max(0, starting_credit - 1)
        data["credit"] = credit
        return credit

    return mutate_json(path, spend)


def mark_pending_sync(
    eng_dir: str | Path,
    command: str,
    command_phase: str,
    ptt_task_id: str,
) -> None:
    path = _sync_path(eng_dir)

    def mark(data: dict[str, Any]) -> None:
        old = data.get("pending") or {}
        commands = list(old.get("commands") or [])
        if old.get("command") and not commands:
            commands = [{"command": old["command"], "phase": old.get("phase", command_phase)}]
        commands.append({"command": command, "phase": command_phase})
        task_id = old.get("ptt_task_id") or ptt_task_id
        if not task_id:
            raise ValueError("pending execution requires a captured active PTT task")
        data["pending"] = {
            "batch_id": old.get("batch_id") or datetime.now(UTC).strftime("%Y%m%d%H%M%S"),
            "commands": commands,
            "phase": command_phase,
            "created_at": old.get("created_at")
            or datetime.now(UTC).isoformat().replace("+00:00", "Z"),
            "ptt_task_id": task_id,
            "ptt_reviewed": False,
            "credit_limit": old.get("credit_limit") or sync_credit_limit(command_phase),
        }

    mutate_json(path, mark)


def clear_pending_sync(eng_dir: str | Path) -> None:
    path = _sync_path(eng_dir)

    def clear(data: dict[str, Any]) -> None:
        data.pop("pending", None)
        data.pop("credit", None)

    mutate_json(path, clear)


def has_pending_sync(eng_dir: str | Path) -> bool:
    data = read_json(_sync_path(eng_dir))
    return "pending" in data


def get_pending_sync(eng_dir: str | Path) -> dict | None:
    data = read_json(_sync_path(eng_dir))
    return data.get("pending")


def rebind_pending_sync(
    eng_dir: str | Path,
    *,
    expected_batch_id: str,
    current_task_id: str,
    replacement_task_id: str,
    note: str,
) -> dict[str, Any]:
    """Rebind a completed pending batch without certifying its PTT review."""
    path = _sync_path(eng_dir)

    def rebind(data: dict[str, Any]) -> dict[str, Any]:
        pending = data.get("pending")
        if not pending:
            raise ValueError("no pending execution batch")
        batch_id = str(pending.get("batch_id") or "")
        if batch_id != expected_batch_id:
            raise ValueError(
                f"stale batch id {expected_batch_id!r}; current pending batch is {batch_id!r}"
            )
        captured = str(pending.get("ptt_task_id") or "")
        if captured != current_task_id:
            raise ValueError(
                f"current task {current_task_id!r} does not match batch task {captured!r}"
            )
        if current_task_id == replacement_task_id:
            raise ValueError("replacement task must differ from the current batch task")

        entry = {
            "timestamp": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
            "batch_id": batch_id,
            "old_task_id": current_task_id,
            "new_task_id": replacement_task_id,
            "note": note.strip(),
        }
        data.setdefault("rebind_audit", []).append(entry)
        pending["ptt_task_id"] = replacement_task_id
        pending["ptt_reviewed"] = False
        pending.pop("ptt_note", None)
        pending.pop("ptt_reviewed_at", None)
        data["pending"] = pending
        return entry

    return mutate_json(path, rebind)


def mark_ptt_reviewed(eng_dir: str | Path, task_id: str, note: str) -> None:
    path = _sync_path(eng_dir)

    def mark(data: dict[str, Any]) -> None:
        pending = data.get("pending")
        if not pending:
            raise ValueError("no pending execution batch")
        pending["ptt_reviewed"] = True
        pending["ptt_task_id"] = task_id
        pending["ptt_note"] = note.strip()
        pending["ptt_reviewed_at"] = datetime.now(UTC).isoformat().replace("+00:00", "Z")
        data["pending"] = pending

    mutate_json(path, mark)


# ---------------------------------------------------------------------------
# Heartbeat
# ---------------------------------------------------------------------------


def _heartbeat_path(eng_dir: str | Path) -> Path:
    return _state_dir(eng_dir) / _HEARTBEAT_FILE


def set_heartbeat_pending(eng_dir: str | Path, reason: str) -> None:
    path = _heartbeat_path(eng_dir)

    def mark(data: dict[str, Any]) -> None:
        data["pending"] = True
        data["reason"] = reason
        data["created_at"] = datetime.now(UTC).isoformat().replace("+00:00", "Z")

    mutate_json(path, mark)


def clear_heartbeat_pending(eng_dir: str | Path) -> None:
    path = _heartbeat_path(eng_dir)

    def clear(data: dict[str, Any]) -> None:
        data["pending"] = False
        data.pop("reason", None)

    mutate_json(path, clear)


def has_heartbeat_pending(eng_dir: str | Path) -> bool:
    data = read_json(_heartbeat_path(eng_dir))
    return data.get("pending", False)


def get_heartbeat_reason(eng_dir: str | Path) -> str | None:
    data = read_json(_heartbeat_path(eng_dir))
    return data.get("reason")


# ---------------------------------------------------------------------------
# Command / message counters
# ---------------------------------------------------------------------------


def _counts_path(eng_dir: str | Path) -> Path:
    return _state_dir(eng_dir) / _COUNTS_FILE


def read_counts(eng_dir: str | Path) -> dict[str, int]:
    data = read_json(_counts_path(eng_dir))
    return {
        "commands": data.get("commands", 0),
        "messages": data.get("messages", 0),
    }


def tick_command(eng_dir: str | Path) -> int:
    path = _counts_path(eng_dir)

    def tick(data: dict[str, Any]) -> int:
        data["commands"] = data.get("commands", 0) + 1
        return data["commands"]

    return mutate_json(path, tick)


def tick_message(eng_dir: str | Path) -> int:
    path = _counts_path(eng_dir)

    def tick(data: dict[str, Any]) -> int:
        data["messages"] = data.get("messages", 0) + 1
        return data["messages"]

    return mutate_json(path, tick)


def record_ok_check(eng_dir: str | Path, command: str, phase: str) -> None:
    path = _counts_path(eng_dir)

    def record(data: dict[str, Any]) -> None:
        data["last_check"] = {
            "command": command,
            "phase": phase,
            "at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        }

    mutate_json(path, record)
