"""Shared state machine — doc-sync, heartbeat, retry detection, last-check recording.

Pure functions with atomic, cross-process-locked file operations. No subprocess calls.
"""

from __future__ import annotations

import contextlib
import json
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

try:  # POSIX
    import fcntl
except ImportError:  # Windows
    fcntl = None
try:  # Windows
    import msvcrt
except ImportError:  # POSIX
    msvcrt = None

from .phases import Phase

# Constants
DEFAULT_SYNC_CREDIT = 5
COMMAND_INTERVAL = 20
MESSAGE_INTERVAL = 30
MAX_BURST_COMMANDS = 20
RETRY_LIMIT = 3

# Commands that are purely local bookkeeping.  Network clients are deliberately
# absent: curl/dig/host/nslookup/whois can touch an engagement target and must
# consume the same bounded review credits as every other violin_exec command.
LOCAL_TOOLS = {"echo", "true", "false", "printf", "pwd", "ls", "cat", "date"}


def is_local_bookkeeping_command(command: str) -> bool:
    """Whether a command is a harmless local bookkeeping action.

    The executor is the only consumer of this classification.  Keeping it here
    avoids a second, divergent LOCAL_TOOLS list in command policy.
    """
    leading = command.strip().split(maxsplit=1)
    return bool(leading) and leading[0] in LOCAL_TOOLS


_STATE_DIR = "state"
_SYNC_FILE = "sync.json"
_HEARTBEAT_FILE = "heartbeat.json"
_COUNTS_FILE = "counts.json"
_LOCK_SUFFIX = ".lock"


def _eng_dir(eng_dir: str | Path) -> Path:
    return Path(eng_dir).resolve()


def _state_dir(eng_dir: str | Path) -> Path:
    p = _eng_dir(eng_dir) / _STATE_DIR
    p.mkdir(parents=True, exist_ok=True)
    return p


def _lock_file(path: Path):
    """Acquire an exclusive advisory lock for the duration of a ``with`` block.

    Uses ``fcntl`` on POSIX and ``msvcrt`` on Windows. The lock is held on the
    target file's directory lockfile (named ``<file>.lock``) so concurrent
    processes serialise writes without racing on the temp swap.
    """
    lock_path = path.with_suffix(path.suffix + ".lock")
    fh = None
    try:
        fh = open(lock_path, "w", encoding="utf-8")  # noqa: SIM115 - closed in finally
    except OSError:
        return contextlib.nullcontext()
    if fcntl is not None:
        try:
            fcntl.flock(fh.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            # Blocking fallback: wait for the lock to free.
            fcntl.flock(fh.fileno(), fcntl.LOCK_EX)
    elif msvcrt is not None:
        # msvcrt has no non-blocking mode; retry briefly.
        deadline = time.monotonic() + 5.0
        while True:
            try:
                msvcrt.locking(fh.fileno(), msvcrt.LK_NBLCK, 1)
                break
            except OSError:
                if time.monotonic() >= deadline:
                    break
                time.sleep(0.05)
    return _FileLock(fh)


class _FileLock:
    def __init__(self, fh):
        self._fh = fh

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        if self._fh is None:
            return False
        try:
            if fcntl is not None:
                fcntl.flock(self._fh.fileno(), fcntl.LOCK_UN)
            elif msvcrt is not None:
                with contextlib.suppress(OSError):
                    msvcrt.locking(self._fh.fileno(), msvcrt.LK_UNLCK, 1)
        finally:
            self._fh.close()
        return False


def _atomic_write(path: Path, data: dict[str, Any]) -> None:
    """Atomic JSON write using tmp + os.replace, guarded by an advisory lock."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with _lock_file(path):
        tmp = path.with_suffix(path.suffix + ".tmp")
        tmp.write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")
        tmp.replace(path)


def _read_json(path: Path) -> dict[str, Any]:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}


# --------------------------------------------------------------------------- #
# Sync credit / pending sync
# --------------------------------------------------------------------------- #


def _sync_path(eng_dir: str | Path) -> Path:
    return _state_dir(eng_dir) / _SYNC_FILE


def sync_credit_remaining(eng_dir: str | Path) -> int:
    data = _read_json(_sync_path(eng_dir))
    return max(0, data.get("credit", DEFAULT_SYNC_CREDIT))


def spend_sync_credit(eng_dir: str | Path) -> int:
    path = _sync_path(eng_dir)
    data = _read_json(path)
    credit = max(0, data.get("credit", DEFAULT_SYNC_CREDIT) - 1)
    data["credit"] = credit
    _atomic_write(path, data)
    return credit


def mark_pending_sync(
    eng_dir: str | Path,
    command: str,
    phase: str,
) -> None:
    path = _sync_path(eng_dir)
    data = _read_json(path)
    old = data.get("pending") or {}
    commands = list(old.get("commands") or [])
    if old.get("command") and not commands:
        commands = [{"command": old["command"], "phase": old.get("phase", phase)}]
    commands.append({"command": command, "phase": phase})
    data["pending"] = {
        "batch_id": old.get("batch_id") or datetime.now(UTC).strftime("%Y%m%d%H%M%S"),
        "commands": commands,
        "phase": phase,
        "created_at": old.get("created_at") or datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        "ptt_reviewed": bool(old.get("ptt_reviewed", False)),
    }
    _atomic_write(path, data)


def clear_pending_sync(eng_dir: str | Path) -> None:
    path = _sync_path(eng_dir)
    data = _read_json(path)
    data.pop("pending", None)
    data["credit"] = DEFAULT_SYNC_CREDIT
    _atomic_write(path, data)


def has_pending_sync(eng_dir: str | Path) -> bool:
    data = _read_json(_sync_path(eng_dir))
    return "pending" in data


def get_pending_sync(eng_dir: str | Path) -> dict | None:
    data = _read_json(_sync_path(eng_dir))
    return data.get("pending")


def mark_ptt_reviewed(eng_dir: str | Path, task_id: str, note: str) -> None:
    path = _sync_path(eng_dir)
    data = _read_json(path)
    pending = data.get("pending")
    if not pending:
        raise ValueError("no pending execution batch")
    pending["ptt_reviewed"] = True
    pending["ptt_task_id"] = task_id
    pending["ptt_note"] = note.strip()
    pending["ptt_reviewed_at"] = datetime.now(UTC).isoformat().replace("+00:00", "Z")
    data["pending"] = pending
    _atomic_write(path, data)


def append_history(
    eng_dir: str | Path, command: str, phase: str, exit_code: int, receipt_path: str = ""
) -> None:
    path = _eng_dir(eng_dir) / "state" / "history.md"
    path.parent.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(UTC).isoformat().replace("+00:00", "Z")
    line = f"- {stamp} | phase={phase} | exit_code={exit_code} | command={command}"
    if receipt_path:
        line += f" | receipt={receipt_path}"
    with path.open("a", encoding="utf-8") as handle:
        handle.write(line + "\n")


def history_contains(eng_dir: str | Path, command: str) -> bool:
    """Return True if ``command`` already appears in the engagement history.

    Used by the self-certify guard to prove a batch finished before review.
    """
    hist = _eng_dir(eng_dir) / "state" / "history.md"
    if not hist.exists():
        return False
    return command in hist.read_text(encoding="utf-8")


# --------------------------------------------------------------------------- #
# Heartbeat
# --------------------------------------------------------------------------- #


def _heartbeat_path(eng_dir: str | Path) -> Path:
    return _state_dir(eng_dir) / _HEARTBEAT_FILE


def set_heartbeat_pending(eng_dir: str | Path, reason: str) -> None:
    path = _heartbeat_path(eng_dir)
    data = _read_json(path)
    data["pending"] = True
    data["reason"] = reason
    data["created_at"] = datetime.now(UTC).isoformat().replace("+00:00", "Z")
    _atomic_write(path, data)


def clear_heartbeat_pending(eng_dir: str | Path) -> None:
    path = _heartbeat_path(eng_dir)
    data = _read_json(path)
    data["pending"] = False
    data.pop("reason", None)
    _atomic_write(path, data)


def has_heartbeat_pending(eng_dir: str | Path) -> bool:
    data = _read_json(_heartbeat_path(eng_dir))
    return data.get("pending", False)


def get_heartbeat_reason(eng_dir: str | Path) -> str | None:
    data = _read_json(_heartbeat_path(eng_dir))
    return data.get("reason")


# --------------------------------------------------------------------------- #
# Command / message counters
# --------------------------------------------------------------------------- #


def _counts_path(eng_dir: str | Path) -> Path:
    return _state_dir(eng_dir) / _COUNTS_FILE


def read_counts(eng_dir: str | Path) -> dict[str, int]:
    data = _read_json(_counts_path(eng_dir))
    return {
        "commands": data.get("commands", 0),
        "messages": data.get("messages", 0),
    }


def tick_command(eng_dir: str | Path) -> int:
    path = _counts_path(eng_dir)
    data = _read_json(path)
    data["commands"] = data.get("commands", 0) + 1
    _atomic_write(path, data)
    return data["commands"]


def tick_message(eng_dir: str | Path) -> int:
    path = _counts_path(eng_dir)
    data = _read_json(path)
    data["messages"] = data.get("messages", 0) + 1
    _atomic_write(path, data)
    return data["messages"]


def record_ok_check(
    eng_dir: str | Path,
    command: str,
    phase: str,
) -> None:
    path = _counts_path(eng_dir)
    data = _read_json(path)
    data["last_check"] = {
        "command": command,
        "phase": phase,
        "at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
    }
    _atomic_write(path, data)


def last_ok_check(eng_dir: str | Path) -> dict | None:
    data = _read_json(_counts_path(eng_dir))
    return data.get("last_check")


# --------------------------------------------------------------------------- #
# Repeat detection
# --------------------------------------------------------------------------- #


def repeat_count(eng_dir: str | Path, command: str) -> int:
    """Count consecutive identical commands at tail of history.md."""
    hist = _eng_dir(eng_dir) / "state" / "history.md"
    if not hist.exists():
        return 0
    lines = hist.read_text(encoding="utf-8").splitlines()
    count = 0
    for line in reversed(lines):
        if command in line:
            count += 1
        elif line.strip():
            break
    return count


# --------------------------------------------------------------------------- #
# Artifact freshness (delegates to bootstrap for canonical paths)
# --------------------------------------------------------------------------- #


def artifacts_are_fresh(eng_dir: str | Path) -> bool:
    """Check if bootstrap artifacts have been updated recently."""
    paths = [
        _eng_dir(eng_dir) / "scope" / "scope.yaml",
        _eng_dir(eng_dir) / "state" / "ptt.md",
        _eng_dir(eng_dir) / "hypotheses.md",
        _eng_dir(eng_dir) / "state" / "history.md",
    ]
    return all(p.exists() for p in paths)


def suppresses_heartbeat(phase: Phase) -> bool:
    """Return True for phases that suppress heartbeat (EXPLOITATION, POST_EXPLOITATION)."""
    return phase in (Phase.EXPLOITATION, Phase.POST_EXPLOITATION)


__all__ = [
    "DEFAULT_SYNC_CREDIT",
    "COMMAND_INTERVAL",
    "MESSAGE_INTERVAL",
    "MAX_BURST_COMMANDS",
    "RETRY_LIMIT",
    "sync_credit_remaining",
    "spend_sync_credit",
    "mark_pending_sync",
    "clear_pending_sync",
    "has_pending_sync",
    "get_pending_sync",
    "set_heartbeat_pending",
    "clear_heartbeat_pending",
    "has_heartbeat_pending",
    "get_heartbeat_reason",
    "read_counts",
    "tick_command",
    "tick_message",
    "record_ok_check",
    "last_ok_check",
    "repeat_count",
    "artifacts_are_fresh",
    "suppresses_heartbeat",
    "LOCAL_TOOLS",
    "is_local_bookkeeping_command",
    "append_history",
    "mark_ptt_reviewed",
    "history_contains",
]
