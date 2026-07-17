"""Guarded process execution, evidence persistence, and receipt registry.

This is the only guard module that uses subprocess. The other modules are pure.
"""

from __future__ import annotations

import contextlib
import os
import re
import shutil
import signal
import subprocess
import threading
import time
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from . import state
from .history import append_history
from .phases import normalize_phase

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
    docker_cwd = "/engagement" if relative == "." else f"/engagement/{relative}"
    prefix = ["docker", "exec", "-i", "-w", docker_cwd, container]
    return prefix + list(argv) if argv is not None else prefix + ["sh", "-lc", command]


def _terminate_pid(pid: int) -> None:
    if pid <= 0:
        return
    if os.name == "nt":
        subprocess.run(
            ["taskkill", "/PID", str(pid), "/T", "/F"],
            capture_output=True,
            check=False,
        )
    else:
        try:
            os.killpg(pid, signal.SIGTERM)
            time.sleep(0.2)
            os.killpg(pid, signal.SIGKILL)
        except ProcessLookupError:
            pass


def _terminate_process(proc: subprocess.Popen) -> None:
    """Terminate a process we directly own, then clean up its process group."""

    if proc.poll() is not None:
        return
    try:
        proc.terminate()
        proc.wait(timeout=1)
        return
    except (OSError, subprocess.TimeoutExpired):
        pass
    _terminate_pid(proc.pid)
    if proc.poll() is None:
        with contextlib.suppress(OSError):
            proc.kill()


def _preview(path: Path) -> str:
    with path.open("rb") as handle:
        return handle.read(PREVIEW_BYTES).decode("utf-8", errors="replace")


def _finalize_background(
    *,
    engagement: Path,
    registry_path: Path,
    manifest_path: Path,
    command: str,
    phase: str,
    exit_code: int,
    status_name: str,
) -> dict[str, Any]:
    with state.lock_file(registry_path):
        record = state.read_json(registry_path)
        if record.get("history_recorded"):
            return record
        if record.get("cancel_requested"):
            status_name = "cancelled"
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
        state.atomic_json(manifest_path, receipt)
        state.atomic_json(registry_path, receipt)
        return receipt


def _monitor_background(
    proc: subprocess.Popen,
    *,
    engagement: Path,
    registry_path: Path,
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
        current = state.read_json(registry_path)
        if current.get("cancel_requested"):
            status_name = "cancelled"
            _terminate_process(proc)
            break
        if time.monotonic() >= deadline:
            status_name = "timed_out"
            _terminate_process(proc)
            break
        try:
            if stdout_path.stat().st_size + stderr_path.stat().st_size > MAX_OUTPUT_BYTES:
                status_name = "output_limited"
                _terminate_process(proc)
                break
        except OSError:
            pass
        time.sleep(0.1)
    try:
        exit_code = proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        _terminate_process(proc)
        exit_code = proc.wait(timeout=5)
    _finalize_background(
        engagement=engagement,
        registry_path=registry_path,
        manifest_path=manifest_path,
        command=command,
        phase=phase,
        exit_code=exit_code,
        status_name=status_name,
    )


def _commit_started_command(engagement: Path, command: str, phase: str, ptt_task_id: str) -> int:
    if state.is_local_bookkeeping_command(command):
        return state.sync_credit_remaining(str(engagement))
    return _commit_guard_state(engagement, command, phase, ptt_task_id)


def _start_background_monitor(
    proc: subprocess.Popen,
    *,
    record: dict[str, Any],
    engagement: Path,
    registry_path: Path,
    manifest_path: Path,
    stdout_path: Path,
    stderr_path: Path,
    command: str,
    phase: str,
    ptt_task_id: str,
    timeout: int,
    execution_id: str,
) -> dict[str, Any]:
    state.atomic_json(manifest_path, record)
    try:
        remaining = _commit_started_command(engagement, command, phase, ptt_task_id)
    except Exception:
        _terminate_process(proc)
        raise
    threading.Thread(
        target=_monitor_background,
        kwargs={
            "proc": proc,
            "engagement": engagement,
            "registry_path": registry_path,
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
    }


def execute(
    command: str,
    *,
    eng_dir: str,
    phase: str,
    backend: str = "local",
    timeout_seconds: Any = DEFAULT_TIMEOUT,
    cwd: str = "",
    label: str = "",
    docker_container: str = "kali-pentest",
    ptt_task_id: str = "",
    argv: list[str] | None = None,
    background: bool = False,
) -> dict[str, Any]:
    """Execute one already-authorized command and persist its complete receipt."""
    engagement = _resolve_engagement(eng_dir)
    workdir = _resolve_cwd(engagement, cwd)
    timeout = _timeout(timeout_seconds)
    execution_id = str(uuid.uuid4())
    started_at = _utc_now()
    stem = f"{started_at[:19].replace(':', '')}-{execution_id[:8]}-{_label(label)}"
    evidence_dir = engagement / "evidence" / "executions"
    stdout_path = evidence_dir / f"{stem}.stdout.txt"
    stderr_path = evidence_dir / f"{stem}.stderr.txt"
    manifest_path = evidence_dir / f"{stem}.json"
    registry_path = engagement / "state" / "executions" / f"{execution_id}.json"
    rel_manifest = manifest_path.relative_to(engagement).as_posix()
    rel_stdout = stdout_path.relative_to(engagement).as_posix()
    rel_stderr = stderr_path.relative_to(engagement).as_posix()

    evidence_dir.mkdir(parents=True, exist_ok=True)

    record: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "execution_id": execution_id,
        "status": "starting",
        "backend": backend,
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
    state.atomic_json(registry_path, record)

    timed_out = False
    output_limited = False
    cancelled = False
    proc: subprocess.Popen | None = None

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
                command, backend, workdir, engagement, docker_container, argv=argv
            )
            proc = subprocess.Popen(process_argv, **popen_kwargs)

            record.update(status="running", pid=proc.pid)
            state.atomic_json(registry_path, record)

            if background:
                return _start_background_monitor(
                    proc,
                    record=record,
                    engagement=engagement,
                    registry_path=registry_path,
                    manifest_path=manifest_path,
                    stdout_path=stdout_path,
                    stderr_path=stderr_path,
                    command=command,
                    phase=phase,
                    ptt_task_id=ptt_task_id,
                    timeout=timeout,
                    execution_id=execution_id,
                )

            deadline = time.monotonic() + timeout
            while proc.poll() is None:
                current = state.read_json(registry_path)
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
        stderr_path.write_text(f"executor error: {exc}\n", encoding="utf-8")

    completed_at = _utc_now()
    receipt = {
        **record,
        "status": "cancelled"
        if cancelled
        else "timed_out"
        if timed_out
        else "output_limited"
        if output_limited
        else "completed",
        "completed_at": completed_at,
        "exit_code": exit_code,
        "timed_out": timed_out,
        "cancelled": cancelled,
        "output_limited": output_limited,
    }
    state.atomic_json(manifest_path, receipt)
    state.atomic_json(registry_path, receipt)

    append_history(engagement, command, phase, exit_code, rel_manifest)

    remaining = _commit_started_command(engagement, command, phase, ptt_task_id)

    return {
        **receipt,
        "executed": True,
        "stdout_preview": _preview(stdout_path),
        "stderr_preview": _preview(stderr_path),
        "sync_required": remaining <= 0,
        "sync_credit_remaining": remaining,
    }


def _commit_guard_state(eng_dir: Path, command: str, phase: str, ptt_task_id: str = "") -> int:
    state.record_ok_check(str(eng_dir), command, phase)
    remaining = state.spend_sync_credit(str(eng_dir))
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
    path = engagement / "state" / "executions" / f"{execution_id}.json"
    # Background finalization replaces this file atomically while status calls
    # may arrive from another thread. On Windows, reading during the replace
    # can transiently raise an OSError, which read_json intentionally maps to
    # an empty document. Serialize the read with the finalizer's lock so a
    # tracked execution is never misreported as missing.
    with state.lock_file(path):
        record = state.read_json(path)
    if not record:
        raise ValueError("execution not found")
    if record.get("background") and record.get("status") == "running":
        pid = record.get("pid")
        if isinstance(pid, int) and pid > 0 and not _pid_is_running(pid):
            record = _finalize_background(
                engagement=engagement,
                registry_path=path,
                manifest_path=engagement / record["evidence_paths"]["manifest"],
                command=record["command"],
                phase=record["phase"],
                exit_code=-1,
                status_name="completed",
            )
    return record


def _pid_is_running(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except OSError:
        return False
    return True


def cancel(eng_dir: str, execution_id: str) -> dict[str, Any]:
    engagement = _resolve_engagement(eng_dir)
    path = engagement / "state" / "executions" / f"{execution_id}.json"
    record = status(str(engagement), execution_id)
    if record.get("status") not in {"starting", "running"}:
        return {**record, "cancel_requested": False, "message": "execution is not running"}

    pid = record.get("pid")
    if not isinstance(pid, int) or pid <= 0:
        raise ValueError("running execution has no valid tracked PID")

    record["cancel_requested"] = True
    record["cancel_requested_at"] = _utc_now()
    state.atomic_json(path, record)
    _terminate_pid(pid)

    return {**record, "message": "cancellation requested for tracked process group"}
