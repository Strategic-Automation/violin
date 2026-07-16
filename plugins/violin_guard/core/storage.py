"""Unified file storage, locking, and JSON serialization utilities."""

from __future__ import annotations

import contextlib
import json
import time
from pathlib import Path
from typing import Any

try:  # POSIX
    import fcntl
except ImportError:  # Windows
    fcntl = None
try:  # Windows
    import msvcrt
except ImportError:  # POSIX
    msvcrt = None


def lock_file(path: Path) -> FileLock:
    """Acquire an exclusive advisory lock for the duration of a ``with`` block.

    Uses ``fcntl`` on POSIX and ``msvcrt`` on Windows. The lock is held on the
    target file's directory lockfile (named ``<file>.lock``) so concurrent
    processes serialise writes without racing on the temp swap.
    """
    lock_path = path.with_suffix(path.suffix + ".lock")
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    # ``msvcrt.locking`` locks bytes, so the file must contain at least one.
    # Opening in binary append mode also avoids truncating a lock file another
    # process has already opened.
    fh = open(lock_path, "a+b")  # noqa: SIM115 - closed in FileLock
    if msvcrt is not None:
        fh.seek(0, 2)
        if fh.tell() == 0:
            fh.write(b"0")
            fh.flush()
        fh.seek(0)
    if fcntl is not None:
        try:
            fcntl.flock(fh.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            # Blocking fallback: wait for the lock to free.
            fcntl.flock(fh.fileno(), fcntl.LOCK_EX)
    elif msvcrt is not None:
        # msvcrt has no non-blocking mode; retry with a generous timeout.
        deadline = time.monotonic() + 20.0
        while True:
            try:
                msvcrt.locking(fh.fileno(), msvcrt.LK_NBLCK, 1)
                break
            except OSError as exc:
                if time.monotonic() >= deadline:
                    fh.close()
                    raise TimeoutError(f"timed out acquiring state lock: {lock_path}") from exc
                time.sleep(0.05)
    return FileLock(fh)


class FileLock:
    def __init__(self, fh):
        self._fh = fh

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        if self._fh is None:
            return False
        try:
            if fcntl is not None:
                fcntl.flock(self._fh.fileno(), fcntl.LOCK_UN)
            elif msvcrt is not None:
                with contextlib.suppress(OSError):
                    msvcrt.locking(self._fh.fileno(), msvcrt.LK_UNLCK, 1)
        finally:
            self._fh.close()
        return False


def read_json(path: Path) -> dict[str, Any]:
    """Read a JSON document, returning an empty dict on error."""
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}


def atomic_json(path: Path, data: dict[str, Any]) -> None:
    """Write JSON atomically by replacing a temporary swap file."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")
    tmp.replace(path)


def mutate_json(path: Path, mutation) -> Any:
    """Apply ``mutation`` to one state document under a single file lock.

    Every state transition must read, modify and replace the document while
    holding the same lock. Locking only the final replace loses updates under
    concurrent tool calls.
    """
    with lock_file(path):
        data = read_json(path)
        result = mutation(data)
        atomic_json(path, data)
        return result
