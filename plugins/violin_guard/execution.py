"""Guarded process execution, evidence persistence, and receipt registry.

This is the only guard module that uses subprocess. The other modules are pure.
"""

from __future__ import annotations

import contextlib
import os
import re
import shutil
import subprocess
import threading
import time
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import psutil

from . import state
from .history import append_history
from .phases import normalize_phase
from .receipt_integrity import seal_execution_receipt
from .runtime_backend import resolve_backend

__all__ = [
    "execute",
    "status",
    "cancel",
    "SCHEMA_VERSION",
    "DEFAULT_TIMEOUT",
    "MAX_TIMEOUT",
    "MIN_TIMEOUT",
    "MAX_OUTPUT_BYTES",
    "PREVIEW_BYTES",
]

SCHEMA_VERSION = 2
DEFAULT_TIMEOUT = 180
MIN_TIMEOUT = 1
MAX_TIMEOUT = 1800
MAX_OUTPUT_BYTES = 10 * 1024 * 1024
PREVIEW_BYTES = 32 * 1024
DOCKER_CONTAINER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")


def _utc_now() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def _resolve_engagement(eng_dir: str) -> Path:
    path = state.resolve_eng_dir(eng_dir)
    if not path.is_dir():
        raise ValueError(f"engagement directory not found: {path}")
    return path


def _resolve_cwd(eng_dir: Path, cwd: str) -> Path:
    candidate = (eng_dir / (cwd or ".")).resolve()
    try:
        candidate.relative_to(eng_dir)
    except ValueError as exc:
        raise ValueError("cwd must stay inside the engagement directory") from exc
    if not candidate.is_dir():
        raise ValueError(f"execution cwd not found: {candidate}")
    return candidate


def _label(value: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9_.-]+", "-", value.strip()).strip("-.")
    return (cleaned or "command")[:64]


def _timeout(value: Any) -> int:
    try:
        parsed = int(value or DEFAULT_TIMEOUT)
    except (TypeError, ValueError) as exc:
        raise ValueError("timeout_seconds must be an integer") from exc
    if not MIN_TIMEOUT <= parsed <= MAX_TIMEOUT:
        raise ValueError(f"timeout_seconds must be between {MIN_TIMEOUT} and {MAX_TIMEOUT}")
    return parsed


def _command_argv(
    command: str,
    backend: str,
    cwd: Path,
    eng_dir: Path,
    container: str,
    argv: list[str] | None = None,
) -> list[str]:
    if argv is not None:
        if not argv or any(
            not isinstance(item, str) or not item or "\x00" in item for item in argv
        ):
            raise ValueError("argv must be a non-empty array of non-empty strings")
        if backend == "local":
            return list(argv)

    if backend == "local":
        if os.name == "nt":
            return [os.environ.get("COMSPEC", "cmd.exe"), "/d", "/s", "/c", command]
        return ["/bin/sh", "-lc", command]

    if backend != "docker":
        raise ValueError("backend must be local or docker")

    if not DOCKER_CONTAINER_RE.fullmatch(container):
        raise ValueError("invalid Docker container name")

    if shutil.which("docker") is None:
        raise ValueError("Docker backend unavailable: docker executable not found")

    relative = cwd.relative_to(eng_dir).as_posix()
    docker_root = f"/engagements/{eng_dir.name}"
    docker_cwd = docker_root if relative == "." else f"{docker_root}/{relative}"
    prefix = ["docker", "exec", "-i", "-w", docker_cwd, container]
    return prefix + list(argv) if argv is not None else prefix + ["sh", "-lc", command]


def _terminate_pid(pid: int) -> None:
    """Recursively terminate a process tree by PID using psutil."""
    if pid <= 0:
        return
    try:
        parent = psutil.Process(pid)
        children = parent.children(recursive=True)
        procs = children + [parent]
        for proc in procs:
            with contextlib.suppress(psutil.NoSuchProcess):
                proc.terminate()
        _, alive = psutil.wait_procs(procs, timeout=2)
        for proc in alive:
            with contextlib.suppress(psutil.NoSuchProcess):
                proc.kill()
    except psutil.NoSuchProcess:
        pass


def _terminate_process(proc: subprocess.Popen) -> None:
    """Terminate a process we directly own, including all of its child process tree."""
    if proc.poll() is not None:
        return
    _terminate_pid(proc.pid)


def _process_create_time(proc: psutil.Process) -> float | None:
    with contextlib.suppress(psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        return float(proc.create_time())
    return None


def _matching_process(record: dict[str, Any]) -> psutil.Process | None:
    """Return the tracked process only when PID and creation time both match."""
    pid = record.get("pid")
    expected = record.get("pid_create_time")
    if not isinstance(pid, int) or pid <= 0 or not isinstance(expected, int | float):
        return None
    try:
        proc = psutil.Process(pid)
        actual = proc.create_time()
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        return None
    return proc if abs(float(actual) - float(expected)) <= 1.0 else None


def _terminate_tracked_process(proc: psutil.Process) -> None:
    """Terminate a process object already verified against its manifest identity."""
    with contextlib.suppress(psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        children = proc.children(recursive=True)
        procs = children + [proc]
        for child in procs:
            with contextlib.suppress(psutil.NoSuchProcess, psutil.AccessDenied):
                child.terminate()
        _, alive = psutil.wait_procs(procs, timeout=2)
        for child in alive:
            with contextlib.suppress(psutil.NoSuchProcess, psutil.AccessDenied):
                child.kill()


def _deadline_expired(record: dict[str, Any]) -> bool:
    deadline = record.get("deadline_at")
    if not isinstance(deadline, str):
        return False
    with contextlib.suppress(ValueError):
        return datetime.now(UTC) >= datetime.fromisoformat(deadline.replace("Z", "+00:00"))
    return False


def _preview(path: Path | None) -> str:
    if path is None or not path.exists():
        return ""
    with path.open("rb") as handle:
        return handle.read(PREVIEW_BYTES).decode("utf-8", errors="replace")


def _find_execution_manifest(engagement: Path, execution_id: str) -> Path | None:
    evidence_dir = engagement / "evidence" / "executions"
    if not evidence_dir.exists():
        return None
    short_id = execution_id[:8]
    candidates = list(evidence_dir.glob(f"*-{short_id}-*.json"))
    direct = evidence_dir / f"{execution_id}.json"
    if direct.exists() and direct not in candidates:
        candidates.append(direct)
    for path in candidates:
        with state.lock_file(path):
            data = state.read_json(path)
            if data.get("execution_id") == execution_id:
                return path
    return None


def _finalize_background(
    *,
    engagement: Path,
    manifest_path: Path,
    command: str,
    phase: str,
    exit_code: int,
    status_name: str,
) -> dict[str, Any]:
    with state.lock_file(manifest_path):
        record = state.read_json(manifest_path)
        if record.get("history_recorded"):
            return record
        if record.get("cancel_requested"):
            status_name = "cancelled"
        stderr_rel = record.get("evidence_paths", {}).get("stderr")
        if stderr_rel:
            stderr_p = engagement / stderr_rel
            if stderr_p.exists() and stderr_p.stat().st_size == 0:
                with contextlib.suppress(OSError):
                    stderr_p.unlink()
                record.setdefault("evidence_paths", {})["stderr"] = None
        receipt = {
            **record,
            "status": status_name,
            "completed_at": _utc_now(),
            "exit_code": exit_code,
            "timed_out": status_name == "timed_out",
            "cancelled": status_name == "cancelled",
            "output_limited": status_name == "output_limited",
            "history_recorded": False,
        }
        append_history(
            engagement,
            command,
            phase,
            exit_code,
            receipt["evidence_paths"]["manifest"],
        )
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
    command: str,
    phase: str,
    timeout: int,
) -> None:
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
    _finalize_background(
        engagement=engagement,
        manifest_path=manifest_path,
        command=command,
        phase=phase,
        exit_code=exit_code,
        status_name=status_name,
    )


def _commit_started_command(
    engagement: Path,
    command: str,
    phase: str,
    ptt_task_id: str,
    sync_reservation: str | None = None,
) -> tuple[int, bool]:
    if state.is_local_bookkeeping_command(command):
        return state.sync_credit_remaining(str(engagement), phase), False
    if sync_reservation:
        state.record_ok_check(str(engagement), command, phase)
        remaining = state.consume_reserved_sync_credit(str(engagement), sync_reservation)
        state.mark_pending_sync(str(engagement), command, phase, ptt_task_id)
        count = state.tick_command(str(engagement))
        from .phases import suppresses_heartbeat

        phase_enum = normalize_phase(phase)
        if count % state.COMMAND_INTERVAL == 0 and not suppresses_heartbeat(phase_enum):
            state.set_heartbeat_pending(
                str(engagement),
                f"Reached {count} executed target commands. Review engagement files for drift.",
            )
        return remaining, True
    return _commit_guard_state(engagement, command, phase, ptt_task_id), False


def _start_background_monitor(
    proc: subprocess.Popen,
    *,
    record: dict[str, Any],
    engagement: Path,
    manifest_path: Path,
    stdout_path: Path,
    stderr_path: Path,
    command: str,
    phase: str,
    ptt_task_id: str,
    sync_reservation: str | None,
    timeout: int,
    execution_id: str,
) -> dict[str, Any]:
    state.atomic_json(manifest_path, record)
    try:
        remaining, consumed = _commit_started_command(
            engagement, command, phase, ptt_task_id, sync_reservation
        )
    except Exception:
        _terminate_process(proc)
        raise
    threading.Thread(
        target=_monitor_background,
        kwargs={
            "proc": proc,
            "engagement": engagement,
            "manifest_path": manifest_path,
            "stdout_path": stdout_path,
            "stderr_path": stderr_path,
            "command": command,
            "phase": phase,
            "timeout": timeout,
        },
        daemon=True,
        name=f"violin-exec-{execution_id[:8]}",
    ).start()
    return {
        **record,
        "executed": True,
        "stdout_preview": "",
        "stderr_preview": "",
        "sync_required": remaining <= 0,
        "sync_credit_remaining": remaining,
        "sync_reservation_consumed": consumed,
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
    background: bool = False,
    sync_reservation: str | None = None,
) -> dict[str, Any]:
    """Execute one already-authorized command and persist its complete receipt."""
    engagement = _resolve_engagement(eng_dir)
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
        "pid": None,
        "background": background,
        "timeout_seconds": timeout,
        "evidence_paths": {
            "manifest": rel_manifest,
            "stdout": rel_stdout,
            "stderr": rel_stderr,
        },
    }
    state.atomic_json(manifest_path, record)

    timed_out = False
    output_limited = False
    cancelled = False
    proc: subprocess.Popen | None = None
    failure_status = ""

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
            deadline_at = datetime.fromtimestamp(datetime.now(UTC).timestamp() + timeout, UTC)
            record.update(
                status="running",
                pid=proc.pid,
                pid_create_time=created,
                deadline_at=deadline_at.isoformat().replace("+00:00", "Z"),
            )
            state.atomic_json(manifest_path, record)

            if background:
                return _start_background_monitor(
                    proc,
                    record=record,
                    engagement=engagement,
                    manifest_path=manifest_path,
                    stdout_path=stdout_path,
                    stderr_path=stderr_path,
                    command=command,
                    phase=phase,
                    ptt_task_id=ptt_task_id,
                    sync_reservation=sync_reservation,
                    timeout=timeout,
                    execution_id=execution_id,
                )

            deadline = time.monotonic() + timeout
            while proc.poll() is None:
                current = state.read_json(manifest_path)
                if current.get("cancel_requested"):
                    cancelled = True
                    _terminate_pid(proc.pid)
                    break
                if time.monotonic() >= deadline:
                    timed_out = True
                    _terminate_pid(proc.pid)
                    break
                stdout_file.flush()
                stderr_file.flush()
                if stdout_path.stat().st_size + stderr_path.stat().st_size > MAX_OUTPUT_BYTES:
                    output_limited = True
                    _terminate_pid(proc.pid)
                    break
                time.sleep(0.1)

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

    completed_at = _utc_now()
    if stderr_path.exists() and stderr_path.stat().st_size == 0:
        with contextlib.suppress(OSError):
            stderr_path.unlink()
        record.setdefault("evidence_paths", {})["stderr"] = None

    receipt = {
        **record,
        "status": failure_status
        or (
            "cancelled"
            if cancelled
            else "timed_out"
            if timed_out
            else "output_limited"
            if output_limited
            else "completed"
        ),
        "completed_at": completed_at,
        "exit_code": exit_code,
        "timed_out": timed_out,
        "cancelled": cancelled,
        "output_limited": output_limited,
    }
    receipt = seal_execution_receipt(receipt, engagement)
    state.atomic_json(manifest_path, receipt)

    append_history(
        engagement,
        command,
        phase,
        exit_code,
        rel_manifest,
        status=str(receipt["status"]),
    )

    if proc is None:
        remaining = state.sync_credit_remaining(str(engagement), phase)
        consumed = False
    else:
        remaining, consumed = _commit_started_command(
            engagement, command, phase, ptt_task_id, sync_reservation
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


def _commit_guard_state(eng_dir: Path, command: str, phase: str, ptt_task_id: str = "") -> int:
    state.record_ok_check(str(eng_dir), command, phase)
    remaining = state.spend_sync_credit(str(eng_dir), phase)
    state.mark_pending_sync(str(eng_dir), command, phase, ptt_task_id)
    count = state.tick_command(str(eng_dir))
    from .phases import suppresses_heartbeat

    phase_enum = normalize_phase(phase)
    if count % state.COMMAND_INTERVAL == 0 and not suppresses_heartbeat(phase_enum):
        state.set_heartbeat_pending(
            str(eng_dir),
            f"Reached {count} executed target commands. Review engagement files for drift.",
        )
    return remaining


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
    if record.get("background") and record.get("status") == "running":
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
                return refreshed
            record = _finalize_background(
                engagement=engagement,
                manifest_path=manifest_path,
                command=record["command"],
                phase=record["phase"],
                exit_code=-1,
                status_name="lost",
            )
        elif _deadline_expired(record):
            _terminate_tracked_process(proc)
            record = _finalize_background(
                engagement=engagement,
                manifest_path=manifest_path,
                command=record["command"],
                phase=record["phase"],
                exit_code=-1,
                status_name="timed_out",
            )
    return record


def cancel(eng_dir: str, execution_id: str) -> dict[str, Any]:
    engagement = _resolve_engagement(eng_dir)
    record = status(str(engagement), execution_id)
    manifest_path = engagement / record["evidence_paths"]["manifest"]
    if record.get("status") not in {"starting", "running"}:
        return {**record, "cancel_requested": False, "message": "execution is not running"}

    proc = _matching_process(record)
    if proc is None:
        manifest_path = engagement / record["evidence_paths"]["manifest"]
        return _finalize_background(
            engagement=engagement,
            manifest_path=manifest_path,
            command=record["command"],
            phase=record["phase"],
            exit_code=-1,
            status_name="lost",
        )

    record["cancel_requested"] = True
    record["cancel_requested_at"] = _utc_now()
    state.atomic_json(manifest_path, record)
    _terminate_tracked_process(proc)

    return {**record, "message": "cancellation requested for tracked process group"}
