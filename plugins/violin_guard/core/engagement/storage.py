"""Engagement path resolution and locked JSON storage."""

from __future__ import annotations

import contextlib
import json
import os
import time
import uuid
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from filelock import FileLock

_STATE_DIR = "state"
_SESSION_FILE = "session.json"


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
