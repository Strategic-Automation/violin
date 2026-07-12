"""Shared helpers for the violin-guard plugin.

Plugin-specific: invoking the guard CLI scripts and parsing their output.
The doc-sync / heartbeat / stuck-loop state machine lives in the core guard
package (``scripts/guard/sync.py``) and is re-exported here so existing plugin
code keeps working without a second copy of the logic.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

_PLUGIN_DIR = Path(__file__).resolve().parent
_PROFILE_HOME = _PLUGIN_DIR.parent.parent  # repo root == profile dir
_GUARD_SCRIPT = _PROFILE_HOME / "scripts" / "violin_guard.py"
_HYPOTHESIS_GUARD_SCRIPT = _PROFILE_HOME / "scripts" / "hypothesis_guard.py"

# Make the core guard importable so the state machine is shared, not copied.
if str(_PROFILE_HOME / "scripts") not in sys.path:
    sys.path.insert(0, str(_PROFILE_HOME / "scripts"))

# Single source of truth for the doc-sync / heartbeat / stuck-loop state machine.
from guard.sync import (  # noqa: E402, I001
    _read_counts as read_counts,
    COMMAND_INTERVAL,
    MAX_BURST_COMMANDS,
    MESSAGE_INTERVAL,
    RETRY_LIMIT,
    artifacts_are_fresh,
    clear_heartbeat_pending,
    clear_pending_sync,
    has_heartbeat_pending,
    has_pending_sync,
    last_ok_check,
    mark_pending_sync,
    record_ok_check,
    repeat_count,
    set_heartbeat_pending,
    spend_sync_credit,
    sync_credit_remaining,
    tick_command,
    tick_message,
)

__all__ = [
    "COMMAND_INTERVAL",
    "MAX_BURST_COMMANDS",
    "MESSAGE_INTERVAL",
    "RETRY_LIMIT",
    "artifacts_are_fresh",
    "clear_heartbeat_pending",
    "clear_pending_sync",
    "has_heartbeat_pending",
    "has_pending_sync",
    "last_ok_check",
    "mark_pending_sync",
    "record_ok_check",
    "repeat_count",
    "set_heartbeat_pending",
    "spend_sync_credit",
    "sync_credit_remaining",
    "tick_command",
    "tick_message",
    "read_counts",
    "run_guard",
    "run_hypothesis_guard",
    "parse_exit",
]


def run_guard(subcommand: str, **kwargs) -> subprocess.CompletedProcess:
    """Invoke `violin_guard.py <subcommand>` with the given CLI flags.

    kwargs are mapped to `--kebab-case` flags; None/empty values are skipped.
    Testable: monkeypatch `subprocess.run` in tests.
    """
    return _run_guard_impl(_GUARD_SCRIPT, subcommand, kwargs)


def run_hypothesis_guard(subcommand: str, **kwargs) -> subprocess.CompletedProcess:
    """Invoke `hypothesis_guard.py <subcommand>` (record/check-hypothesis)."""
    return _run_guard_impl(_HYPOTHESIS_GUARD_SCRIPT, subcommand, kwargs)


def _run_guard_impl(script: Path, subcommand: str, kwargs: dict) -> subprocess.CompletedProcess:
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


def parse_exit(result: subprocess.CompletedProcess) -> dict:
    """Return a structured result: status + stdout lines grouped by prefix."""
    out = result.stdout or ""
    block, review, ok = [], [], []
    for line in out.splitlines():
        if line.startswith("BLOCK:"):
            block.append(line[len("BLOCK:") :].strip())
        elif line.startswith("REVIEW:"):
            review.append(line[len("REVIEW:") :].strip())
        elif line.startswith("OK:"):
            ok.append(line[len("OK:") :].strip())
    return {
        "exit_code": result.returncode,
        "block": block,
        "review": review,
        "ok": ok,
        "raw": out.strip(),
    }
