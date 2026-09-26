"""Launch and track guarded command executions."""

from __future__ import annotations

import contextlib
import os
import subprocess
import time
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import psutil

from ..core.commands.http_proof import normalize_http_proof_flags
from ..core.engagement import state
from ..engine.runtime_backend import resolve_backend
from .execution_lifecycle import (
    _commit_started_command,
    _finalize_execution,
    _start_background_monitor,
)
from .execution_support import (
    DEFAULT_TIMEOUT,
    MAX_OUTPUT_BYTES,
    SCHEMA_VERSION,
    _command_argv,
    _evidence_snapshot,
    _EvidenceOutputLocks,
    _label,
    _preview,
    _process_create_time,
    _resolve_cwd,
    _resolve_engagement,
    _terminate_pid,
    _terminate_process,
    _timeout,
    _utc_now,
    _validate_evidence_outputs,
)


def _execute(
    command: str,
    *,
    eng_dir: str,
    phase: str,
    backend: str = "auto",
    timeout_seconds: Any = DEFAULT_TIMEOUT,
    cwd: str = "",
    label: str = "",
    docker_container: str = "kali-pentest",
    ptt_task_id: str = "",
    argv: list[str] | None = None,
    evidence_outputs: list[str] | None = None,
    background: bool = False,
    sync_reservation: str | None = None,
    resolved_engagement: Path,
    declared_outputs: list[str],
    output_locks: _EvidenceOutputLocks,
) -> dict[str, Any]:
    """Execute one already-authorized command and persist its complete receipt."""
    # Rewrite curl/wget HTTP probes to capture the response status line (add -i)
    # so saved evidence always carries a literal HTTP/1.x status line. Lives in
    # core.commands.http_proof; applied before the receipt is sealed and before the
    # process runs so both the manifest and the executed argv record the fix.
    requested_command = command
    command = normalize_http_proof_flags(command)
    engagement = resolved_engagement
    workdir = _resolve_cwd(engagement, cwd)
    timeout = _timeout(timeout_seconds)
    resolution = resolve_backend(backend, engagement, container=docker_container)
    execution_id = str(uuid.uuid4())
    started_at = _utc_now()
    stem = f"{started_at[:19].replace(':', '')}-{execution_id[:8]}-{_label(label)}"
    evidence_dir = engagement / "evidence" / "executions"
    stdout_path = evidence_dir / f"{stem}.stdout.txt"
    stderr_path = evidence_dir / f"{stem}.stderr.txt"
    manifest_path = evidence_dir / f"{stem}.json"
    rel_manifest = manifest_path.relative_to(engagement).as_posix()
    rel_stdout = stdout_path.relative_to(engagement).as_posix()
    rel_stderr = stderr_path.relative_to(engagement).as_posix()

    state.ensure_dir(evidence_dir)

    record: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "execution_id": execution_id,
        "status": "starting",
        "backend": resolution.resolved,
        "runtime": resolution.to_dict(),
        "command": command,
        "phase": phase,
        "cwd": str(workdir),
        "started_at": started_at,
        "intent_at": started_at,
        "ptt_task_id": ptt_task_id,
        "sync_reservation": sync_reservation,
        "pid": None,
        "background": background,
        "timeout_seconds": timeout,
        "evidence_paths": {
            "manifest": rel_manifest,
            "stdout": rel_stdout,
            "stderr": rel_stderr,
        },
        "declared_evidence_outputs": declared_outputs,
        "declared_outputs_before": _evidence_snapshot(engagement, declared_outputs),
    }
    if command != requested_command:
        # The probe was rewritten to capture its status line. Keep the command the
        # caller asked for so the receipt explains the flag that was injected.
        record["requested_command"] = requested_command
        record["command_note"] = "status capture injected for HTTP proof"
    state.atomic_json(manifest_path, record)

    timed_out = False
    output_limited = False
    cancelled = False
    proc: subprocess.Popen | None = None
    failure_status = ""
    accounting: tuple[int, bool, int, bool] | None = None

    try:
        with stdout_path.open("wb") as stdout_file, stderr_path.open("wb") as stderr_file:
            popen_kwargs: dict[str, Any] = {
                "cwd": str(workdir),
                "stdout": stdout_file,
                "stderr": stderr_file,
                "stdin": subprocess.DEVNULL,
                "shell": False,
            }
            if os.name == "nt":
                popen_kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP
            else:
                popen_kwargs["start_new_session"] = True

            process_argv = _command_argv(
                command, resolution.resolved, workdir, engagement, resolution.container, argv=argv
            )
            proc = subprocess.Popen(process_argv, **popen_kwargs)

            created = _process_create_time(psutil.Process(proc.pid))
            if created is None:
                _terminate_process(proc)
                raise RuntimeError("could not record process creation time")
            deadline_at = datetime.now(UTC) + timedelta(seconds=timeout)
            record.update(
                status="running",
                pid=proc.pid,
                pid_create_time=created,
                deadline_at=deadline_at.isoformat().replace("+00:00", "Z"),
            )
            with state.lock_file(manifest_path):
                current = state.read_json(manifest_path)
                if current.get("cancel_requested"):
                    record["cancel_requested"] = True
                    record["cancel_requested_at"] = current.get("cancel_requested_at")
                state.atomic_json(manifest_path, record)
            accounting = _commit_started_command(
                engagement,
                command,
                phase,
                ptt_task_id,
                execution_id,
                sync_reservation,
            )

            if background:
                return _start_background_monitor(
                    proc,
                    record=record,
                    engagement=engagement,
                    manifest_path=manifest_path,
                    stdout_path=stdout_path,
                    stderr_path=stderr_path,
                    timeout=timeout,
                    execution_id=execution_id,
                    accounting=accounting,
                    output_locks=output_locks,
                )

            deadline = time.monotonic() + timeout
            last_manifest_read = -1.0
            while proc.poll() is None:
                now = time.monotonic()
                if now - last_manifest_read >= 1.0:
                    # Cancel manifests and size checks are polled on a 1s cadence;
                    # the process itself runs under a hard deadline so a 1s
                    # granularity does not delay termination materially.
                    last_manifest_read = now
                    current = state.read_json(manifest_path)
                    if current.get("cancel_requested"):
                        cancelled = True
                        _terminate_pid(proc.pid)
                        break
                    if now >= deadline:
                        timed_out = True
                        _terminate_pid(proc.pid)
                        break
                    stdout_file.flush()
                    stderr_file.flush()
                    if stdout_path.stat().st_size + stderr_path.stat().st_size > MAX_OUTPUT_BYTES:
                        output_limited = True
                        _terminate_pid(proc.pid)
                        break
                time.sleep(0.05)

            try:
                exit_code = proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                _terminate_pid(proc.pid)
                exit_code = proc.wait(timeout=5)
    except Exception as exc:
        exit_code = -1
        failure_status = "failed_to_start" if proc is None else "failed_to_track"
        if proc is not None:
            with contextlib.suppress(Exception):
                _terminate_process(proc)
        stderr_path.write_text(f"executor error: {exc}\n", encoding="utf-8")

    if proc is not None and accounting is None:
        accounting = _commit_started_command(
            engagement,
            command,
            phase,
            ptt_task_id,
            execution_id,
            sync_reservation,
        )
    receipt = _finalize_execution(
        engagement=engagement,
        manifest_path=manifest_path,
        exit_code=exit_code,
        status_name=failure_status
        or (
            "cancelled"
            if cancelled
            else "timed_out"
            if timed_out
            else "output_limited"
            if output_limited
            else "completed"
        ),
        timed_out=timed_out,
        cancelled=cancelled,
        output_limited=output_limited,
    )
    output_locks.release()
    remaining, consumed = (
        (accounting[0], accounting[1])
        if accounting is not None
        else (state.sync_credit_remaining(str(engagement), phase), False)
    )

    return {
        **receipt,
        "executed": proc is not None,
        "stdout_preview": _preview(stdout_path),
        "stderr_preview": _preview(stderr_path),
        "sync_required": remaining <= 0,
        "sync_credit_remaining": remaining,
        "sync_reservation_consumed": consumed,
        "sync_reservation_released": False,
    }


def execute(
    command: str,
    *,
    eng_dir: str,
    phase: str,
    backend: str = "auto",
    timeout_seconds: Any = DEFAULT_TIMEOUT,
    cwd: str = "",
    label: str = "",
    docker_container: str = "kali-pentest",
    ptt_task_id: str = "",
    argv: list[str] | None = None,
    evidence_outputs: list[str] | None = None,
    background: bool = False,
    sync_reservation: str | None = None,
) -> dict[str, Any]:
    """Execute with exclusive ownership of each declared output until finalization."""
    engagement = _resolve_engagement(eng_dir)
    declared_outputs = _validate_evidence_outputs(engagement, evidence_outputs)
    output_locks = _EvidenceOutputLocks(engagement, declared_outputs)
    try:
        return _execute(
            command,
            eng_dir=eng_dir,
            phase=phase,
            backend=backend,
            timeout_seconds=timeout_seconds,
            cwd=cwd,
            label=label,
            docker_container=docker_container,
            ptt_task_id=ptt_task_id,
            argv=argv,
            evidence_outputs=evidence_outputs,
            background=background,
            sync_reservation=sync_reservation,
            resolved_engagement=engagement,
            declared_outputs=declared_outputs,
            output_locks=output_locks,
        )
    finally:
        if not output_locks.transferred:
            output_locks.release()
