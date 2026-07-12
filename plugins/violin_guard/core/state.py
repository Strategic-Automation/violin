"""Shared state machine — doc-sync, heartbeat, retry detection, last-check recording.

Pure functions with atomic file operations. No subprocess calls (except CLI bridge at end).
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .phases import Phase

# Constants
DEFAULT_SYNC_CREDIT = 5
COMMAND_INTERVAL = 20
MESSAGE_INTERVAL = 30
MAX_BURST_COMMANDS = 20
RETRY_LIMIT = 3

# Commands that are purely local bookkeeping. Network clients remain guarded.
LOCAL_TOOLS = {"echo", "true", "false", "printf", "pwd", "ls", "cat", "date"}

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


def _atomic_write(path: Path, data: dict[str, Any]) -> None:
    """Atomic JSON write using tmp + os.replace."""
    path.parent.mkdir(parents=True, exist_ok=True)
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
    data["pending"] = {"batch_id": old.get("batch_id") or datetime.now(UTC).strftime("%Y%m%d%H%M%S"),
                        "commands": commands, "phase": phase,
                        "created_at": old.get("created_at") or datetime.now(UTC).isoformat().replace("+00:00", "Z"),
                        "ptt_reviewed": bool(old.get("ptt_reviewed", False))}
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
    path = _sync_path(eng_dir); data = _read_json(path); pending = data.get("pending")
    if not pending: raise ValueError("no pending execution batch")
    pending["ptt_reviewed"] = True; pending["ptt_task_id"] = task_id
    pending["ptt_note"] = note.strip(); pending["ptt_reviewed_at"] = datetime.now(UTC).isoformat().replace("+00:00", "Z")
    data["pending"] = pending; _atomic_write(path, data)

def append_history(eng_dir: str | Path, command: str, phase: str, exit_code: int, receipt_path: str = "") -> None:
    path = _eng_dir(eng_dir) / "state" / "history.md"; path.parent.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(UTC).isoformat().replace("+00:00", "Z")
    line = f"- {stamp} | phase={phase} | exit_code={exit_code} | command={command}"
    if receipt_path: line += f" | receipt={receipt_path}"
    with path.open("a", encoding="utf-8") as handle: handle.write(line + "\n")


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
    for p in paths:
        if not p.exists():
            return False
    return True


def suppresses_heartbeat(phase: "Phase") -> bool:
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
    "append_history", "mark_ptt_reviewed",
]


# --------------------------------------------------------------------------- #
# CLI bridge — compatibility with existing tools.py
# --------------------------------------------------------------------------- #


def _run_guard_impl(script: Path, subcommand: str, kwargs: dict) -> subprocess.CompletedProcess:
    """Invoke a guard CLI script with the given arguments."""
    cmd = [sys.executable, str(script), subcommand]
    for key, val in kwargs.items():
        if val is None or val == "":
            continue
        flag = "--" + key.replace("_", "-")
        cmd.append(flag)
        if isinstance(val, bool):
            if not val:
                cmd.pop()
            continue
        cmd.append(str(val))
    return subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        env={**os.environ, "PYTHONIOENCODING": "utf-8"},
    )


def run_guard(subcommand: str, **kwargs) -> subprocess.CompletedProcess:
    """Invoke `violin_guard.py <subcommand>` with the given CLI flags.

    kwargs are mapped to `--kebab-case` flags; None/empty values are skipped.
    Testable: monkeypatch `subprocess.run` in tests.
    """
    _PLUGIN_DIR = Path(__file__).resolve().parent.parent  # plugins/violin_guard
    _PROFILE_HOME = _PLUGIN_DIR.parent.parent  # repo root
    _GUARD_SCRIPT = _PROFILE_HOME / "scripts" / "violin_guard.py"
    return _run_guard_impl(_GUARD_SCRIPT, subcommand, kwargs)


def run_hypothesis_guard(subcommand: str, **kwargs) -> subprocess.CompletedProcess:
    """Invoke `hypothesis_guard.py <subcommand>` (record/check-hypothesis)."""
    _PLUGIN_DIR = Path(__file__).resolve().parent.parent  # plugins/violin_guard
    _PROFILE_HOME = _PLUGIN_DIR.parent.parent  # repo root
    _HYPOTHESIS_GUARD_SCRIPT = _PROFILE_HOME / "scripts" / "hypothesis_guard.py"
    return _run_guard_impl(_HYPOTHESIS_GUARD_SCRIPT, subcommand, kwargs)


def parse_exit(result: subprocess.CompletedProcess) -> dict:
    """Return a structured result: status + stdout lines grouped by prefix."""
    out = result.stdout or ""
    block, review, ok = [], [], []
    for line in out.splitlines():
        if line.startswith("BLOCK:"):
            block.append(line[len("BLOCK:"):].strip())
        elif line.startswith("REVIEW:"):
            review.append(line[len("REVIEW:"):].strip())
        elif line.startswith("OK:"):
            ok.append(line[len("OK:"):].strip())
    return {
        "exit_code": result.returncode,
        "block": block,
        "review": review,
        "ok": ok,
        "raw": out.strip(),
    }
