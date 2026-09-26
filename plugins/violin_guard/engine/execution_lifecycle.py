"""Receipt finalization and execution lifecycle operations."""

from __future__ import annotations

import contextlib
import re
import subprocess
import threading
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from ..core.engagement import state
from ..core.evidence.history import append_history
from ..core.evidence.receipt_integrity import seal_execution_receipt
from .execution_support import (
    MAX_OUTPUT_BYTES,
    _deadline_expired,
    _EvidenceOutputLocks,
    _find_execution_manifest,
    _matching_process,
    _produced_outputs,
    _resolve_engagement,
    _terminate_process,
    _terminate_tracked_process,
    _utc_now,
)


def _finalize_execution(
    *,
    engagement: Path,
    manifest_path: Path,
    exit_code: int,
    status_name: str,
    timed_out: bool = False,
    cancelled: bool = False,
    output_limited: bool = False,
) -> dict[str, Any]:
    """Persist a terminal intent, then idempotently publish history and receipt.

    The intent makes the chosen outcome recoverable if the process exits after
    history is appended but before its signed receipt is atomically replaced.
    Every finalizer narrows the receipt's evidence identity the same way, so a
    command that runs in the background or is reconciled from ``status()`` seals
    exactly what its own command wrote — never a batch-mate's output.
    """
    with state.lock_file(manifest_path):
        record = state.read_json(manifest_path)
        if record.get("history_recorded"):
            return record
        terminal = record.get("terminal")
        if not isinstance(terminal, dict):
            if record.get("cancel_requested"):
                status_name = "cancelled"
                cancelled = True
            terminal = {
                "status": status_name,
                "completed_at": _utc_now(),
                "exit_code": exit_code,
                "timed_out": timed_out or status_name == "timed_out",
                "cancelled": cancelled or status_name == "cancelled",
                "output_limited": output_limited or status_name == "output_limited",
            }
            record["terminal"] = terminal
            record["status"] = "finalizing"
            state.atomic_json(manifest_path, record)

        stderr_rel = record.get("evidence_paths", {}).get("stderr")
        if stderr_rel:
            stderr_p = engagement / stderr_rel
            if stderr_p.exists() and stderr_p.stat().st_size == 0:
                with contextlib.suppress(OSError):
                    stderr_p.unlink()
                record.setdefault("evidence_paths", {})["stderr"] = None
        record["declared_evidence_outputs"] = _produced_outputs(engagement, record)
        record["terminal"] = terminal
        state.atomic_json(manifest_path, record)
        command = str(record.get("command") or "")
        phase = str(record.get("phase") or "")
        execution_id = str(record.get("execution_id") or "")

    # The durable terminal intent and manifest lock are released before taking
    # the history lock. Retries find the same intent and history append is keyed
    # by execution_id, so two finalizers cannot create duplicate entries.
    append_history(
        engagement,
        command,
        phase,
        int(terminal["exit_code"]),
        str(record.get("evidence_paths", {}).get("manifest") or ""),
        status=str(terminal["status"]),
        execution_id=execution_id,
    )

    with state.lock_file(manifest_path):
        record = state.read_json(manifest_path)
        if record.get("history_recorded"):
            return record
        terminal = record.get("terminal")
        if not isinstance(terminal, dict):
            raise RuntimeError("execution terminal intent disappeared during finalization")
        receipt = {key: value for key, value in record.items() if key != "terminal"}
        receipt.update(terminal)
        receipt["receipt_kind"] = "execution"
        receipt["history_recorded"] = True
        receipt = seal_execution_receipt(receipt, engagement)
        state.atomic_json(manifest_path, receipt)
        return receipt


def _monitor_background(
    proc: subprocess.Popen,
    *,
    engagement: Path,
    manifest_path: Path,
    stdout_path: Path,
    stderr_path: Path,
    timeout: int,
    output_locks: _EvidenceOutputLocks,
) -> None:
    try:
        deadline = time.monotonic() + timeout
        status_name = "completed"
        while proc.poll() is None:
            current = state.read_json(manifest_path)
            if current.get("cancel_requested"):
                status_name = "cancelled"
                _terminate_process(proc)
                break
            if time.monotonic() >= deadline:
                status_name = "timed_out"
                _terminate_process(proc)
                break
            with contextlib.suppress(OSError):
                if stdout_path.stat().st_size + stderr_path.stat().st_size > MAX_OUTPUT_BYTES:
                    status_name = "output_limited"
                    _terminate_process(proc)
                    break
            time.sleep(0.1)
        try:
            exit_code = proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            _terminate_process(proc)
            exit_code = proc.wait(timeout=5)
        _finalize_execution(
            engagement=engagement,
            manifest_path=manifest_path,
            exit_code=exit_code,
            status_name=status_name,
            timed_out=status_name == "timed_out",
            cancelled=status_name == "cancelled",
            output_limited=status_name == "output_limited",
        )
    finally:
        output_locks.release()


def _commit_started_command(
    engagement: Path,
    command: str,
    phase: str,
    ptt_task_id: str,
    execution_id: str,
    sync_reservation: str | None = None,
) -> tuple[int, bool, int, bool]:
    if state.is_local_bookkeeping_command(command):
        return (
            state.sync_credit_remaining(str(engagement), phase),
            False,
            state.read_counts(str(engagement))["commands"],
            False,
        )
    return state.commit_execution_start(
        str(engagement), command, phase, ptt_task_id, execution_id, sync_reservation
    )


def _start_background_monitor(
    proc: subprocess.Popen,
    *,
    record: dict[str, Any],
    engagement: Path,
    manifest_path: Path,
    stdout_path: Path,
    stderr_path: Path,
    timeout: int,
    execution_id: str,
    accounting: tuple[int, bool, int, bool],
    output_locks: _EvidenceOutputLocks,
) -> dict[str, Any]:
    remaining, consumed, _, _ = accounting
    monitor = threading.Thread(
        target=_monitor_background,
        kwargs={
            "proc": proc,
            "engagement": engagement,
            "manifest_path": manifest_path,
            "stdout_path": stdout_path,
            "stderr_path": stderr_path,
            "timeout": timeout,
            "output_locks": output_locks,
        },
        daemon=True,
        name=f"violin-exec-{execution_id[:8]}",
    )
    monitor.start()
    output_locks.transfer()
    return {
        **record,
        "executed": True,
        "stdout_preview": "",
        "stderr_preview": "",
        "sync_required": remaining <= 0,
        "sync_credit_remaining": remaining,
        "sync_reservation_consumed": consumed,
    }


def status(eng_dir: str, execution_id: str) -> dict[str, Any]:
    engagement = _resolve_engagement(eng_dir)
    if not re.fullmatch(r"[0-9a-fA-F-]{36}", execution_id):
        raise ValueError("invalid execution_id")
    manifest_path = _find_execution_manifest(engagement, execution_id)
    if not manifest_path:
        raise ValueError("execution not found")
    # Background finalization replaces this file atomically while status calls
    # may arrive from another thread. On Windows, reading during the replace
    # can transiently raise an OSError, which read_json intentionally maps to
    # an empty document. Serialize the read with the finalizer's lock so a
    # tracked execution is never misreported as missing.
    with state.lock_file(manifest_path):
        record = state.read_json(manifest_path)
    if not record:
        raise ValueError("execution not found")
    if record.get("status") == "finalizing":
        terminal = record.get("terminal") or {}
        return _finalize_execution(
            engagement=engagement,
            manifest_path=manifest_path,
            exit_code=int(terminal.get("exit_code", -1)),
            status_name=str(terminal.get("status") or "lost"),
            timed_out=bool(terminal.get("timed_out")),
            cancelled=bool(terminal.get("cancelled")),
            output_limited=bool(terminal.get("output_limited")),
        )
    if record.get("status") == "starting":
        # A persisted intent without a process identity is ambiguous after a
        # short launch window. Charge it conservatively before recording lost.
        intent_at = record.get("intent_at") or record.get("started_at")
        if isinstance(intent_at, str):
            with contextlib.suppress(ValueError):
                age = datetime.now(UTC) - datetime.fromisoformat(intent_at.replace("Z", "+00:00"))
                if age < timedelta(seconds=5):
                    return record
        _reconcile_execution_accounting(engagement, record)
        return _finalize_execution(
            engagement=engagement,
            manifest_path=manifest_path,
            exit_code=-1,
            status_name="lost",
        )
    if record.get("status") == "running":
        proc = _matching_process(record)
        if proc is None:
            # A live monitor can be finalizing a normally exited process at
            # the same moment status observes that its PID has disappeared.
            # Give that atomic writer a short opportunity before classifying
            # an untracked process as lost (important after application restart).
            time.sleep(0.1)
            with state.lock_file(manifest_path):
                refreshed = state.read_json(manifest_path)
            if refreshed.get("status") != "running":
                if refreshed.get("status") == "finalizing":
                    terminal = refreshed.get("terminal") or {}
                    return _finalize_execution(
                        engagement=engagement,
                        manifest_path=manifest_path,
                        exit_code=int(terminal.get("exit_code", -1)),
                        status_name=str(terminal.get("status") or "lost"),
                        timed_out=bool(terminal.get("timed_out")),
                        cancelled=bool(terminal.get("cancelled")),
                        output_limited=bool(terminal.get("output_limited")),
                    )
                return refreshed
            _reconcile_execution_accounting(engagement, record)
            record = _finalize_execution(
                engagement=engagement,
                manifest_path=manifest_path,
                exit_code=-1,
                status_name="lost",
            )
        elif _deadline_expired(record):
            _terminate_tracked_process(proc)
            _reconcile_execution_accounting(engagement, record)
            record = _finalize_execution(
                engagement=engagement,
                manifest_path=manifest_path,
                exit_code=-1,
                status_name="timed_out",
                timed_out=True,
            )
    return record


def _reconcile_execution_accounting(engagement: Path, record: dict[str, Any]) -> None:
    """Finish launch accounting after a process identity was durably recorded."""
    execution_id = str(record.get("execution_id") or "")
    ptt_task_id = str(record.get("ptt_task_id") or "")
    if not execution_id or not ptt_task_id:
        return
    _commit_started_command(
        engagement,
        str(record.get("command") or ""),
        str(record.get("phase") or ""),
        ptt_task_id,
        execution_id,
        str(record.get("sync_reservation") or "") or None,
    )


def cancel(eng_dir: str, execution_id: str) -> dict[str, Any]:
    engagement = _resolve_engagement(eng_dir)
    record = status(str(engagement), execution_id)
    manifest_path = engagement / record["evidence_paths"]["manifest"]
    if record.get("status") not in {"starting", "running"}:
        return {**record, "cancel_requested": False, "message": "execution is not running"}

    if record.get("status") == "starting" and not record.get("pid"):
        manifest_path = engagement / record["evidence_paths"]["manifest"]
        with state.lock_file(manifest_path):
            current = state.read_json(manifest_path)
            if current.get("status") == "starting" and not current.get("pid"):
                current["cancel_requested"] = True
                current["cancel_requested_at"] = _utc_now()
                state.atomic_json(manifest_path, current)
                return {**current, "message": "cancellation requested during launch"}
            record = current
        if record.get("status") not in {"starting", "running"}:
            return {
                **record,
                "cancel_requested": False,
                "message": "execution is not running",
            }

    proc = _matching_process(record)
    if proc is None:
        manifest_path = engagement / record["evidence_paths"]["manifest"]
        _reconcile_execution_accounting(engagement, record)
        return _finalize_execution(
            engagement=engagement,
            manifest_path=manifest_path,
            exit_code=-1,
            status_name="lost",
        )

    record["cancel_requested"] = True
    record["cancel_requested_at"] = _utc_now()
    state.atomic_json(manifest_path, record)
    _terminate_tracked_process(proc)

    return {**record, "message": "cancellation requested for tracked process group"}
