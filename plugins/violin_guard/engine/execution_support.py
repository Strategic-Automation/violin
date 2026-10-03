"""Shared command and evidence helpers for guarded execution."""

from __future__ import annotations

import contextlib
import hashlib
import os
import re
import shutil
import subprocess
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import psutil
from filelock import FileLock
from filelock import Timeout as FileLockTimeout

from ..core.engagement import state
from ..core.evidence.receipt_integrity import file_digest

SCHEMA_VERSION = 2
DEFAULT_TIMEOUT = 180
MIN_TIMEOUT = 1
MAX_TIMEOUT = 1800
MAX_OUTPUT_BYTES = 10 * 1024 * 1024
PREVIEW_BYTES = 32 * 1024
DOCKER_CONTAINER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")


class _EvidenceOutputLocks:
    """Keep declared output paths exclusive until their command is finalized."""

    def __init__(self, engagement: Path, declared: list[str]) -> None:
        self._locks: list[FileLock] = []
        self._released = False
        self._transferred = False
        if not declared:
            return
        lock_root = engagement / "state" / "evidence-output-locks"
        state.ensure_dir(lock_root)
        try:
            for value in sorted(set(declared)):
                digest = hashlib.sha256(value.encode("utf-8")).hexdigest()
                lock = FileLock(str(lock_root / f"{digest}.lock"), thread_local=False)
                try:
                    lock.acquire(timeout=0)
                except FileLockTimeout as exc:
                    raise ValueError(
                        "an evidence output is already in use by another execution"
                    ) from exc
                self._locks.append(lock)
        except BaseException:
            self.release()
            raise

    def release(self) -> None:
        if self._released:
            return
        for lock in reversed(self._locks):
            lock.release()
        self._released = True

    @property
    def transferred(self) -> bool:
        return self._transferred

    def transfer(self) -> None:
        self._transferred = True


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


def _evidence_snapshot(engagement: Path, declared: list[str]) -> dict[str, dict[str, Any]]:
    """Per-file content digest and stat: the observation provenance is judged on.

    Neither signal alone can tell what a command touched. A probe that rewrites
    a file byte-for-byte changes no digest; a probe that rewrites content while
    preserving the timestamp changes no stat (`cp -p`, `rsync -t`, `os.utime`
    after write, coarse-timestamp filesystems). Recording both lets the
    finalizer detect either kind of write, instead of silently discarding proof
    the agent actually produced. A file is described as absent (``None``) when
    it is missing, so a command that creates its declared output is detected.
    """
    snapshot: dict[str, dict[str, Any]] = {}
    for value in declared:
        path = engagement / value
        if path.is_file() and not path.is_symlink():
            stat = path.stat()
            snapshot[value] = {
                "sha256": file_digest(path),
                "mtime_ns": stat.st_mtime_ns,
            }
        else:
            snapshot[value] = {"sha256": None, "mtime_ns": None}
    return snapshot


def _was_written(before: Any, after: dict[str, Any]) -> bool:
    """Whether a declared file's observed state differs from its own baseline.

    ``before`` is this run's snapshot entry, or a bare digest from a record
    written before the snapshot shape existed. A file absent at baseline and
    present now was created; a moved mtime is a write even when the bytes are
    identical; a changed digest is a write even when the timestamp is preserved.
    """
    if isinstance(before, dict):
        return (before.get("sha256"), before.get("mtime_ns")) != (
            after["sha256"],
            after["mtime_ns"],
        )
    # Legacy baseline: content is the only signal the old record carries.
    return after["sha256"] != before


def _produced_outputs(engagement: Path, record: dict[str, Any]) -> list[str]:
    """The declared files this command actually wrote.

    A receipt's evidence identity is what its own command produced. Files the
    command left alone belong to whoever produced them, so a receipt never seals
    a batch-mate's output. Idempotent: narrowing an already-narrowed record
    against the same baseline yields the same set, so retries are safe.
    """
    baseline = record.get("declared_outputs_before")
    declared = record.get("declared_evidence_outputs") or []
    if not isinstance(baseline, dict) or not isinstance(declared, list):
        return declared
    values = [str(value) for value in declared]
    after = _evidence_snapshot(engagement, values)
    return [value for value in values if _was_written(baseline.get(value), after[value])]
