"""Engagement state API, semantic progress tracking, and local command classification."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from ...core.commands.bash_ast import parse_bash_segments
from ...core.commands.targets import extract_target_candidates
from ..runtime_state import (
    ExecutionAccount,
    HeartbeatState,
    LastCheck,
    PendingBatch,
    PendingCommand,
    RebindAuditEntry,
    Reservation,
    RuntimeState,
    load_runtime_state,
    timestamp,
)
from .runtime import (
    _RUNTIME_FILE,
    COMMAND_INTERVAL,
    DEFAULT_SYNC_CREDIT,
    PHASE_SYNC_CREDIT,
    _mutate_runtime,
    _read_runtime,
    _runtime_path,
    clear_heartbeat_pending,
    clear_pending_sync,
    commit_execution_start,
    get_heartbeat_reason,
    get_pending_sync,
    has_heartbeat_pending,
    has_pending_sync,
    read_counts,
    rebind_pending_sync,
    release_reserved_sync_credit,
    reserve_sync_credit,
    set_heartbeat_pending,
    sync_credit_limit,
    sync_credit_remaining,
    tick_message,
)
from .storage import (
    _SESSION_FILE,
    _STATE_DIR,
    _atomic_write,
    _eng_root,
    _state_dir,
    atomic_json,
    atomic_text,
    ensure_dir,
    lock_file,
    mutate_json,
    read_json,
    record_session_id,
    resolve_eng_dir,
    resolve_session_id,
    workflow_lock,
)

__all__ = [
    "COMMAND_INTERVAL",
    "DEFAULT_SYNC_CREDIT",
    "PHASE_SYNC_CREDIT",
    "MAX_BURST_COMMANDS",
    "LOCAL_TOOLS",
    "_STATE_DIR",
    "_SESSION_FILE",
    "_RUNTIME_FILE",
    "_runtime_path",
    "_read_runtime",
    "_mutate_runtime",
    "_eng_root",
    "resolve_eng_dir",
    "resolve_session_id",
    "record_session_id",
    "ensure_dir",
    "_state_dir",
    "lock_file",
    "workflow_lock",
    "read_json",
    "_atomic_write",
    "atomic_json",
    "atomic_text",
    "mutate_json",
    "ExecutionAccount",
    "HeartbeatState",
    "LastCheck",
    "PendingBatch",
    "PendingCommand",
    "RebindAuditEntry",
    "Reservation",
    "RuntimeState",
    "load_runtime_state",
    "timestamp",
    "sync_credit_limit",
    "sync_credit_remaining",
    "reserve_sync_credit",
    "release_reserved_sync_credit",
    "commit_execution_start",
    "clear_pending_sync",
    "has_pending_sync",
    "get_pending_sync",
    "rebind_pending_sync",
    "set_heartbeat_pending",
    "clear_heartbeat_pending",
    "has_heartbeat_pending",
    "get_heartbeat_reason",
    "read_counts",
    "tick_message",
    "is_local_bookkeeping_command",
    "record_semantic_review",
    "record_research_attempt",
    "semantic_lock",
]

MAX_BURST_COMMANDS = 20
LOCAL_TOOLS = {"echo", "true", "false", "printf", "pwd", "ls", "cat", "date"}
_SEMANTIC_FILE = "semantic-progress.json"


def is_local_bookkeeping_command(command: str) -> bool:
    """Whether a command is a harmless local bookkeeping action."""
    segments = parse_bash_segments(command)
    if len(segments) != 1:
        return False
    segment = segments[0]
    if segment.executable not in LOCAL_TOOLS or segment.redirects:
        return False
    return not extract_target_candidates(command)


def _recorded_findings(eng_dir: Path) -> int:
    """How many findings this engagement has recorded so far.

    A review that produced a finding is progress even when it re-cites an
    already-seen evidence path or describes the result in prose instead of the
    literal ``validated``/``rejected`` outcome - punishing that is what made the
    anti-stuck hint fire on productive batches. Imported here because
    ``findings`` imports this module at import time.
    """
    from ...core.evidence import findings

    try:
        return len(findings.load_findings(eng_dir))
    except (OSError, ValueError, KeyError):
        return 0


def record_semantic_review(
    eng_dir: str | Path,
    *,
    task_id: str,
    hypothesis_id: str,
    skill: str,
    technique: str,
    outcome: str,
    evidence_paths: list[str],
    next_action: str,
    next_technique: str,
) -> dict[str, Any]:
    """Track evidence-backed progress and advisory anti-stuck state.

    This state supplies execution hints; it does not block commands or batch sync.

    The anti-stuck lock is meant to catch *circular* recon — repeating the same
    path without learning.  It therefore counts evidence *novelty*, not raw
    ``violin_review_batch`` calls.  A review resets the no-progress counter only
    when it actually produced something new — a fresh evidence path not seen on
    any previously recorded technique, a decisive ``outcome``
    (``validated`` or ``rejected``), a finding recorded since the previous review,
    or a genuine pivot where ``next_technique``
    differs from the current ``technique`` (a new attack path).  Repeating
    already-recorded evidence keeps the counter growing, which is exactly the
    circular recon the lock exists to catch.
    """

    path = _state_dir(eng_dir) / _SEMANTIC_FILE
    key = "|".join((task_id, hypothesis_id, skill, technique.strip().lower()))
    clean_evidence_paths = [path_item for path_item in evidence_paths if path_item]
    decisive = outcome.strip().lower() in {"validated", "rejected"}
    pivoted = bool(
        next_technique.strip().lower()
        and next_technique.strip().lower() != technique.strip().lower()
    )

    def record(data: dict[str, Any]) -> dict[str, Any]:
        entries = data.setdefault("entries", {})
        entry = entries.get(key, {"count": 0})
        # Evidence novelty: a path counts as new only if it was not already
        # recorded on any technique in this engagement (tracked via each
        # entry's ``evidence_paths``).  Re-citing the same evidence is circular.
        seen_paths = {
            item for prior in entries.values() for item in prior.get("evidence_paths") or []
        }
        recorded_findings = _recorded_findings(eng_dir)
        new_finding = recorded_findings > int(data.get("findings") or 0)
        novel = bool(set(clean_evidence_paths) - seen_paths) or decisive or new_finding
        # Reset the no-progress counter when the review produced something new
        # or pivoted to a new attack path; otherwise keep it growing as a stuck
        # repetition.
        productive = novel or pivoted
        count = 0 if productive else int(entry.get("count") or 0) + 1
        entry.update(
            {
                "count": count,
                "outcome": outcome,
                "evidence_paths": clean_evidence_paths,
                "next_action": next_action,
                "next_technique": next_technique,
                "pivoted": pivoted,
                "updated_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
            }
        )
        entries[key] = entry
        if novel:
            # Counts are the current no-progress streak, not lifetime history.
            # Keep prior outcomes/evidence while clearing stale technique counts.
            for prior in entries.values():
                prior["count"] = 0
        lock = data.get("lock") or {}
        # Whole-engagement stuck signal: total no-progress reviews across all
        # keys. Novel evidence resets it, so a busy CTF loop stays open; a pivot
        # alone neither rescues an active lock nor re-arms it without a research
        # attempt (see below).
        total_stuck = sum(
            int(item.get("count") or 0) for item in entries.values() if not item.get("pivoted")
        )
        if novel or (lock and data.get("research_attempts") and pivoted):
            data.pop("lock", None)
        elif total_stuck >= 5 and not pivoted and not novel:
            data["lock"] = {
                "key": key,
                "count": total_stuck,
                "reason": "five technique no-progress reviews without a pivot or evidence",
            }
        data["findings"] = max(recorded_findings, int(data.get("findings") or 0))
        warning = total_stuck >= 3
        locked = bool(data.get("lock"))
        return {
            "count": count,
            "warning": warning,
            "locked": locked,
            "warning_reason": (
                f"{total_stuck} unproductive reviews remain across techniques. "
                "Semantic-progress warnings and locks are separate from the batch sync lock."
                if warning
                else ""
            ),
            "next_action": (
                "Use violin_review_batch with new evidence_paths, outcome=validated/rejected, or a different next_technique; prose in note/next_action does not count as new evidence. Record a research attempt before a technique pivot when required."
                if locked
                else "Pivot using next_technique or cite new evidence_paths in violin_review_batch; note/next_action prose alone does not establish progress."
                if warning
                else ""
            ),
        }

    return mutate_json(path, record)


def record_research_attempt(eng_dir: str | Path, tool_name: str, success: bool) -> None:
    """Record an actual web research-tool attempt for semantic-lock recovery."""

    path = _state_dir(eng_dir) / _SEMANTIC_FILE

    def record(data: dict[str, Any]) -> None:
        attempts = data.setdefault("research_attempts", [])
        attempts.append(
            {
                "tool": tool_name,
                "success": success,
                "timestamp": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
            }
        )
        data["research_attempts"] = attempts[-20:]

    mutate_json(path, record)


def semantic_lock(eng_dir: str | Path) -> dict[str, Any] | None:
    return read_json(_state_dir(eng_dir) / _SEMANTIC_FILE).get("lock")
