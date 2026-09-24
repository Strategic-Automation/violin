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
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import psutil

from plugins.violin_guard.core.commands.http_proof import normalize_http_proof_flags
from plugins.violin_guard.core.engagement import state
from plugins.violin_guard.core.engagement.phases import normalize_phase, suppresses_heartbeat
from plugins.violin_guard.core.evidence.history import append_history
from plugins.violin_guard.core.evidence.receipt_integrity import seal_execution_receipt
from plugins.violin_guard.engine.runtime_backend import resolve_backend

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


def _validate_evidence_outputs(engagement: Path, values: list[str] | None) -> list[str]:
    """Normalize explicit receipt-bound outputs without inspecting command text."""
    evidence_root = (engagement / "evidence").resolve()
    normalized: list[str] = []
    for value in values or []:
        relative = Path(value)
        if relative.is_absolute():
            raise ValueError("evidence_outputs paths must be engagement-relative")
        candidate = (engagement / relative).resolve()
        if not candidate.is_relative_to(evidence_root):
            raise ValueError("evidence_outputs paths must stay beneath evidence/")
        current = engagement / relative
        while current != engagement:
            if current.is_symlink():
                raise ValueError("evidence_outputs paths must not traverse symlinks")
            current = current.parent
        canonical = candidate.relative_to(engagement).as_posix()
        if canonical not in normalized:
            normalized.append(canonical)
    return normalized


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
    with contextlib.suppress(psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        _terminate_tracked_process(psutil.Process(pid))


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
        missing_outputs = [
            value
            for value in record.get("declared_evidence_outputs") or []
            if not (engagement / value).is_file()
        ]
        terminal.setdefault("missing_evidence_outputs", missing_outputs)
        terminal.setdefault("evidence_complete", not terminal["missing_evidence_outputs"])
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
    _finalize_execution(
        engagement=engagement,
        manifest_path=manifest_path,
        exit_code=exit_code,
        status_name=status_name,
        timed_out=status_name == "timed_out",
        cancelled=status_name == "cancelled",
        output_limited=status_name == "output_limited",
    )


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
) -> dict[str, Any]:
    remaining, consumed, _, _ = accounting
    threading.Thread(
        target=_monitor_background,
        kwargs={
            "proc": proc,
            "engagement": engagement,
            "manifest_path": manifest_path,
            "stdout_path": stdout_path,
            "stderr_path": stderr_path,
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
    evidence_outputs: list[str] | None = None,
    background: bool = False,
    sync_reservation: str | None = None,
) -> dict[str, Any]:
    """Execute one already-authorized command and persist its complete receipt."""
    # Rewrite curl/wget HTTP probes to capture the response status line (add -i)
    # so saved evidence always carries a literal HTTP/1.x status line. Lives in
    # core.commands.http_proof; applied before the receipt is sealed and before the
    # process runs so both the manifest and the executed argv record the fix.
    requested_command = command
    command = normalize_http_proof_flags(command)
    engagement = _resolve_engagement(eng_dir)
    declared_outputs = _validate_evidence_outputs(engagement, evidence_outputs)
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


def _commit_guard_state(eng_dir: Path, command: str, phase: str, ptt_task_id: str = "") -> int:
    state.record_ok_check(str(eng_dir), command, phase)
    remaining = state.spend_sync_credit(str(eng_dir), phase)
    state.mark_pending_sync(str(eng_dir), command, phase, ptt_task_id)
    count = state.tick_command(str(eng_dir))
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
