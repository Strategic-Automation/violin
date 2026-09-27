"""Atomic operations on versioned engagement runtime state."""

from __future__ import annotations

import time
import uuid
from pathlib import Path
from typing import Any

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
from .storage import _state_dir, atomic_json, lock_file

DEFAULT_SYNC_CREDIT = 5
COMMAND_INTERVAL = 50
_RUNTIME_FILE = "runtime.json"
PHASE_SYNC_CREDIT = {
    "RECON": 10,
    "VULN_RESEARCH": 10,
    "EXPLOITATION": 20,
    "POST_EXPLOITATION": 20,
    "PRIVESC": 20,
    "FLAGS": 20,
}


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
