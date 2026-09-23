"""State machine, advisory file locking, and JSON storage."""

from __future__ import annotations

import contextlib
import json
import os
import time
import uuid
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from filelock import FileLock

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
from .phases import normalize_phase, suppresses_heartbeat

# Constants

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
_RUNTIME_FILE = "runtime.json"
_SESSION_FILE = "session.json"
_SEMANTIC_FILE = "semantic-progress.json"


# Path helpers


def _eng_root() -> Path:
    """Return Violin's stable profile/repository root for relative paths."""
    override = os.environ.get("VIOLIN_ENG_ROOT", "").strip()
    if override:
        return Path(override).expanduser().resolve()
    container_root = Path("/violin")
    if container_root.exists() and (container_root / "engagements").exists():
        return container_root.resolve()
    return Path(__file__).resolve().parents[4]


def resolve_eng_dir(eng_dir: str | Path) -> Path:
    """Resolve an engagement directory path (absolute or relative to profile root)."""
    env_root = (
        Path(os.environ.get("ENG_DIR", "").strip()).expanduser().resolve()
        if os.environ.get("ENG_DIR", "").strip()
        else None
    )

    if not str(eng_dir).strip() or str(eng_dir).strip() == ".":
        if env_root is not None:
            return env_root
        cwd = Path.cwd().resolve()
        if (cwd / "scope" / "scope.yaml").exists() or (cwd / "hypotheses.md").exists():
            return cwd
        return _eng_root()

    path = Path(eng_dir).expanduser()
    if not path.is_absolute():
        profile_candidate = (_eng_root() / path).resolve()
        cwd_candidate = (Path.cwd() / path).resolve()
        if not profile_candidate.exists() and cwd_candidate.exists():
            return cwd_candidate
        resolved = profile_candidate
    else:
        resolved = path.resolve()

    return resolved


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
        path = _state_dir(eng_dir) / _SESSION_FILE
        with lock_file(path):
            atomic_json(path, {"session_id": session_id.strip()})


def ensure_dir(path: Path) -> Path:
    """Ensure directory exists fail-safe against symlinks and cross-platform FileExistsError [Errno 17]."""
    try:
        path.mkdir(parents=True, exist_ok=True)
    except FileExistsError:
        if not path.exists():
            raise
    return path


def _state_dir(eng_dir: str | Path) -> Path:
    state_path = resolve_eng_dir(eng_dir) / _STATE_DIR
    ensure_dir(state_path)
    return state_path


# Storage primitives


@contextmanager
def lock_file(path: Path):
    """Acquire an exclusive advisory lock on ``path`` for the duration of a ``with`` block."""
    lock_path = path.with_suffix(path.suffix + ".lock")
    ensure_dir(lock_path.parent)
    with FileLock(str(lock_path), timeout=20):
        yield


@contextmanager
def workflow_lock(eng_dir: str | Path):
    """Serialize multi-file workflow transitions for one engagement.

    Callers acquire this lock before any narrower JSON or receipt file lock.
    """
    lock_path = _state_dir(eng_dir) / "workflow.lock"
    with FileLock(str(lock_path), timeout=20):
        yield


def read_json(path: Path) -> dict[str, Any]:
    """Read a JSON document, returning an empty dict on missing file or non-dict root.

    Raises OSError or json.JSONDecodeError on corrupt/locked file reads when the file exists,
    preventing mutate_json from overwriting existing state with empty dictionaries.
    """
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except (OSError, json.JSONDecodeError):
        # On read failure when file exists, attempt up to 3 retries for transient locks
        for attempt in range(3):
            time.sleep(0.02 * (attempt + 1))
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
                return data if isinstance(data, dict) else {}
            except (OSError, json.JSONDecodeError):
                pass
        raise


def _atomic_write(path: Path, content: str) -> None:
    """Write text atomically by replacing a temporary swap file with retry on Windows."""
    ensure_dir(path.parent)
    tmp = path.with_name(f"{path.name}.{uuid.uuid4().hex}.tmp")
    with tmp.open("w", encoding="utf-8", newline="") as temporary_file:
        temporary_file.write(content)
    try:
        for attempt in range(5):
            try:
                tmp.replace(path)
                return
            except PermissionError:
                if attempt == 4:
                    raise
                time.sleep(0.02 * (attempt + 1))
    finally:
        if tmp.exists():
            with contextlib.suppress(OSError):
                tmp.unlink()


def atomic_json(path: Path, data: dict[str, Any]) -> None:
    """Write JSON atomically by replacing a temporary swap file."""
    _atomic_write(path, json.dumps(data, indent=2, sort_keys=True))


def atomic_text(path: Path, content: str) -> None:
    """Write one UTF-8 text document with an atomic replace."""
    _atomic_write(path, content)


def mutate_json(path: Path, mutation) -> Any:
    """Apply ``mutation`` to one state document under a single file lock."""
    with lock_file(path):
        data = read_json(path)
        result = mutation(data)
        atomic_json(path, data)
        return result


# Local command classification


def is_local_bookkeeping_command(command: str) -> bool:
    """Whether a command is a harmless local bookkeeping action."""
    segments = parse_bash_segments(command)
    if len(segments) != 1:
        return False
    segment = segments[0]
    if segment.executable not in LOCAL_TOOLS or segment.redirects:
        return False
    return not extract_target_candidates(command)


# Versioned executor runtime state


def _runtime_path(eng_dir: str | Path) -> Path:
    return _state_dir(eng_dir) / _RUNTIME_FILE


def _read_runtime(eng_dir: str | Path) -> RuntimeState:
    path = _runtime_path(eng_dir)
    with lock_file(path):
        return load_runtime_state(path)


def _mutate_runtime(eng_dir: str | Path, mutation) -> Any:
    path = _runtime_path(eng_dir)
    with lock_file(path):
        runtime = load_runtime_state(path)
        result = mutation(runtime)
        # Revalidate the full document so nested mutations cannot bypass the
        # typed persistence boundary. The replacement is one atomic commit.
        validated = RuntimeState.model_validate(runtime.model_dump(mode="json"), strict=True)
        atomic_json(path, validated.model_dump(mode="json"))
        return result


def sync_credit_limit(phase: str | None = None) -> int:
    key = str(phase or "").strip().upper().replace("-", "_")
    return PHASE_SYNC_CREDIT.get(key, DEFAULT_SYNC_CREDIT)


def sync_credit_remaining(eng_dir: str | Path, phase: str | None = None) -> int:
    credit = _read_runtime(eng_dir).sync.credit
    return max(0, credit if credit is not None else sync_credit_limit(phase))


def spend_sync_credit(eng_dir: str | Path, phase: str) -> int:
    def spend(runtime: RuntimeState) -> int:
        starting_credit = runtime.sync.credit
        credit = max(
            0, (starting_credit if starting_credit is not None else sync_credit_limit(phase)) - 1
        )
        runtime.sync.credit = credit
        return credit

    return _mutate_runtime(eng_dir, spend)


def reserve_sync_credit(eng_dir: str | Path, phase: str, count: int) -> str:
    """Atomically reserve credit for a burst before any command starts."""
    if count < 1:
        raise ValueError("a sync reservation must contain at least one command")

    def reserve(runtime: RuntimeState) -> str:
        current = runtime.sync.credit
        credit = max(0, current if current is not None else sync_credit_limit(phase))
        if credit < count:
            raise ValueError(f"insufficient sync credit for burst: need {count}, have {credit}")
        reservation_id = f"burst-{uuid.uuid4().hex}"
        runtime.sync.credit = credit - count
        runtime.sync.reservations[reservation_id] = Reservation(
            phase=phase, remaining=count, created_at=timestamp()
        )
        return reservation_id

    return _mutate_runtime(eng_dir, reserve)


def consume_reserved_sync_credit(eng_dir: str | Path, reservation_id: str) -> int:
    """Consume one previously reserved slot without decrementing credit twice."""

    def consume(runtime: RuntimeState) -> int:
        reservation = runtime.sync.reservations.get(reservation_id)
        if reservation is None or reservation.remaining < 1:
            raise ValueError("sync reservation is missing or exhausted")
        if reservation.remaining == 1:
            del runtime.sync.reservations[reservation_id]
        else:
            runtime.sync.reservations[reservation_id] = reservation.model_copy(
                update={"remaining": reservation.remaining - 1}
            )
        return max(0, runtime.sync.credit or 0)

    return _mutate_runtime(eng_dir, consume)


def release_reserved_sync_credit(eng_dir: str | Path, reservation_id: str) -> int:
    """Return every unconsumed slot in a reservation to the sync window."""

    def release(runtime: RuntimeState) -> int:
        reservation = runtime.sync.reservations.pop(reservation_id, None)
        if reservation is not None:
            runtime.sync.credit = (runtime.sync.credit or 0) + reservation.remaining
        return max(0, runtime.sync.credit or 0)

    return _mutate_runtime(eng_dir, release)


def mark_pending_sync(
    eng_dir: str | Path, command: str, command_phase: str, ptt_task_id: str
) -> None:
    def mark(runtime: RuntimeState) -> None:
        old = runtime.sync.pending
        commands = list(old.commands) if old else []
        commands.append(PendingCommand(command=command, phase=command_phase))
        task_id = old.ptt_task_id if old and old.ptt_task_id else ptt_task_id
        if not task_id:
            raise ValueError("pending execution requires a captured active PTT task")
        runtime.sync.pending = PendingBatch(
            batch_id=old.batch_id if old else str(uuid.uuid4()),
            commands=commands,
            phase=command_phase,
            created_at=old.created_at if old else timestamp(),
            ptt_task_id=task_id,
            ptt_reviewed=False,
            credit_limit=(
                old.credit_limit if old and old.credit_limit else sync_credit_limit(command_phase)
            ),
        )

    _mutate_runtime(eng_dir, mark)


def commit_execution_start(
    eng_dir: str | Path,
    command: str,
    command_phase: str,
    ptt_task_id: str,
    execution_id: str,
    sync_reservation: str | None = None,
) -> tuple[int, bool, int, bool]:
    """Atomically account one launched execution once in the versioned runtime document."""
    if not execution_id:
        raise ValueError("execution accounting requires an execution_id")
    if not ptt_task_id:
        raise ValueError("pending execution requires a captured active PTT task")

    phase_enum = normalize_phase(command_phase)

    def account(runtime: RuntimeState) -> tuple[int, bool, int, bool]:
        prior = runtime.sync.execution_accounts.get(execution_id)
        if prior is None:
            consumed = False
            if sync_reservation:
                reservation = runtime.sync.reservations.get(sync_reservation)
                if reservation is None or reservation.remaining < 1:
                    raise ValueError("sync reservation is missing or exhausted")
                if reservation.remaining == 1:
                    del runtime.sync.reservations[sync_reservation]
                else:
                    runtime.sync.reservations[sync_reservation] = reservation.model_copy(
                        update={"remaining": reservation.remaining - 1}
                    )
                remaining = max(0, runtime.sync.credit or 0)
                consumed = True
            else:
                credit = runtime.sync.credit
                remaining = max(
                    0,
                    (credit if credit is not None else sync_credit_limit(command_phase)) - 1,
                )
                runtime.sync.credit = remaining

            pending = runtime.sync.pending
            commands = list(pending.commands) if pending else []
            commands.append(
                PendingCommand(
                    command=command,
                    phase=command_phase,
                    execution_id=execution_id,
                )
            )
            runtime.sync.pending = PendingBatch(
                batch_id=pending.batch_id if pending else str(uuid.uuid4()),
                commands=commands,
                phase=command_phase,
                created_at=pending.created_at if pending else timestamp(),
                ptt_task_id=(
                    pending.ptt_task_id if pending and pending.ptt_task_id else ptt_task_id
                ),
                ptt_reviewed=False,
                credit_limit=(
                    pending.credit_limit
                    if pending and pending.credit_limit
                    else sync_credit_limit(command_phase)
                ),
            )
            runtime.sync.execution_accounts[execution_id] = ExecutionAccount(
                command=command,
                phase=command_phase,
                reserved=consumed,
                accounted_at=timestamp(),
            )
        else:
            remaining = max(0, runtime.sync.credit or 0)
            consumed = prior.reserved

        counted = execution_id not in runtime.counts.execution_ids
        if counted:
            runtime.counts.commands += 1
            runtime.counts.execution_ids.append(execution_id)
            runtime.counts.last_check = LastCheck(
                command=command,
                phase=command_phase,
                at=timestamp(),
                execution_id=execution_id,
            )
        count = runtime.counts.commands
        if counted and count % COMMAND_INTERVAL == 0 and not suppresses_heartbeat(phase_enum):
            runtime.heartbeat = HeartbeatState(
                pending=True,
                reason=f"Reached {count} executed target commands. Review engagement files for drift.",
                created_at=timestamp(),
            )
        return remaining, consumed, count, counted

    return _mutate_runtime(eng_dir, account)


def clear_pending_sync(eng_dir: str | Path) -> None:
    def clear(runtime: RuntimeState) -> None:
        runtime.sync.pending = None
        runtime.sync.credit = None
        runtime.sync.reservations.clear()

    _mutate_runtime(eng_dir, clear)


def has_pending_sync(eng_dir: str | Path) -> bool:
    return _read_runtime(eng_dir).sync.pending is not None


def get_pending_sync(eng_dir: str | Path) -> dict[str, Any] | None:
    pending = _read_runtime(eng_dir).sync.pending
    return pending.model_dump(mode="json", exclude_none=True) if pending else None


def rebind_pending_sync(
    eng_dir: str | Path,
    *,
    expected_batch_id: str,
    current_task_id: str,
    replacement_task_id: str,
    note: str,
) -> dict[str, Any]:
    """Rebind a completed pending batch without certifying its PTT review."""

    def rebind(runtime: RuntimeState) -> dict[str, Any]:
        pending = runtime.sync.pending
        if pending is None:
            raise ValueError("no pending execution batch")
        if pending.batch_id != expected_batch_id:
            raise ValueError(
                f"stale batch id {expected_batch_id!r}; current pending batch is {pending.batch_id!r}"
            )
        if pending.ptt_task_id != current_task_id:
            raise ValueError(
                f"current task {current_task_id!r} does not match batch task {pending.ptt_task_id!r}"
            )
        if current_task_id == replacement_task_id:
            raise ValueError("replacement task must differ from the current batch task")
        entry = RebindAuditEntry(
            timestamp=timestamp(),
            batch_id=pending.batch_id,
            old_task_id=current_task_id,
            new_task_id=replacement_task_id,
            note=note.strip(),
        )
        runtime.sync.rebind_audit.append(entry)
        runtime.sync.pending = pending.model_copy(
            update={
                "ptt_task_id": replacement_task_id,
                "ptt_reviewed": False,
                "ptt_note": None,
                "ptt_reviewed_at": None,
            }
        )
        return entry.model_dump(mode="json")

    return _mutate_runtime(eng_dir, rebind)


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
    research_attempted: bool = False,
) -> dict[str, Any]:
    """Track evidence-backed technique-pivot progress and the anti-stuck lock.

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
        return {
            "count": count,
            "warning": total_stuck >= 3,
            "locked": bool(data.get("lock")),
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


# ---------------------------------------------------------------------------
# Heartbeat and counters share one versioned runtime document
# ---------------------------------------------------------------------------


def set_heartbeat_pending(eng_dir: str | Path, reason: str) -> None:
    def mark(runtime: RuntimeState) -> None:
        runtime.heartbeat = HeartbeatState(pending=True, reason=reason, created_at=timestamp())

    _mutate_runtime(eng_dir, mark)


def clear_heartbeat_pending(eng_dir: str | Path) -> None:
    def clear(runtime: RuntimeState) -> None:
        runtime.heartbeat.pending = False
        runtime.heartbeat.reason = None

    _mutate_runtime(eng_dir, clear)


def has_heartbeat_pending(eng_dir: str | Path) -> bool:
    return _read_runtime(eng_dir).heartbeat.pending


def get_heartbeat_reason(eng_dir: str | Path) -> str | None:
    return _read_runtime(eng_dir).heartbeat.reason


def read_counts(eng_dir: str | Path) -> dict[str, int]:
    counts = _read_runtime(eng_dir).counts
    return {"commands": counts.commands, "messages": counts.messages}


def tick_command(eng_dir: str | Path) -> int:
    def tick(runtime: RuntimeState) -> int:
        runtime.counts.commands += 1
        return runtime.counts.commands

    return _mutate_runtime(eng_dir, tick)


def tick_message(eng_dir: str | Path) -> int:
    def tick(runtime: RuntimeState) -> int:
        runtime.counts.messages += 1
        return runtime.counts.messages

    for attempt in range(3):
        try:
            return _mutate_runtime(eng_dir, tick)
        except OSError:
            if attempt == 2:
                raise
            time.sleep(0.02 * (attempt + 1))
    raise RuntimeError("unreachable")


def record_ok_check(eng_dir: str | Path, command: str, phase: str) -> None:
    def record(runtime: RuntimeState) -> None:
        runtime.counts.last_check = LastCheck(command=command, phase=phase, at=timestamp())

    _mutate_runtime(eng_dir, record)
