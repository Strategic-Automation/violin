"""History file I/O — append, search, staleness, and repeat detection.

All history operations are centralised here to avoid duplication between the
state machine (which previously owned append/contains/repeat) and the guard
checks (which owned the staleness check).
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from .state import ensure_dir, lock_file, resolve_eng_dir

_COMMAND_MARKER = " | command="
_COMMAND_LENGTH_MARKER = " | command_length="
_RECEIPT_MARKER = " | receipt="


def normalize_command(command: str) -> str:
    """Normalize whitespace and newlines in a command string for reliable history matching."""
    if not command:
        return ""
    lines = command.splitlines()
    cleaned_parts = [part.strip() for part in lines if part.strip()]
    return " ".join(cleaned_parts)


def _history_path(eng_dir: str | Path) -> Path:
    return resolve_eng_dir(eng_dir) / "state" / "history.md"


def append_history(
    eng_dir: str | Path,
    command: str,
    phase: str,
    exit_code: int,
    receipt_path: str = "",
    status: str = "",
) -> None:
    """Append one execution record to history.md under an advisory lock."""
    path = _history_path(eng_dir)
    ensure_dir(path.parent)
    stamp = datetime.now(UTC).isoformat().replace("+00:00", "Z")
    clean_command = normalize_command(command) if "\n" in command else command
    status_field = f" | status={status}" if status else ""
    line = (
        f"- {stamp} | phase={phase} | exit_code={exit_code}{status_field} | command={clean_command}"
        f"{_COMMAND_LENGTH_MARKER}{len(clean_command)}"
    )
    if receipt_path:
        line += f"{_RECEIPT_MARKER}{receipt_path}"
    with lock_file(path), path.open("a", encoding="utf-8") as handle:
        handle.write(line + "\n")


def history_contains(eng_dir: str | Path, command: str) -> bool:
    """Return True if ``command`` appears anywhere in history.md.

    Used by the self-certify guard to prove a batch finished before review.
    """
    hist = _history_path(eng_dir)
    if not hist.exists():
        return False
    norm_target = normalize_command(command)
    for line in hist.read_text(encoding="utf-8").splitlines():
        rec = _recorded_command(line)
        if rec == command or (rec is not None and normalize_command(rec) == norm_target):
            return True
    return False


def _recorded_command(line: str) -> str | None:
    """Read one command field, including legacy records without a length."""

    if _COMMAND_MARKER not in line:
        return None
    payload = line.split(_COMMAND_MARKER, 1)[1]
    command, marker, metadata = payload.rpartition(_COMMAND_LENGTH_MARKER)
    if marker:
        length_text = metadata.split(_RECEIPT_MARKER, 1)[0]
        try:
            expected_length = int(length_text)
        except ValueError:
            expected_length = -1
        if expected_length >= 0 and len(command) == expected_length:
            return command

    command, marker, _receipt = payload.rpartition(_RECEIPT_MARKER)
    return command if marker else payload


def check_history_staleness(
    eng_dir: str | Path, command: str, *, allow_pending_repeat: bool = False
) -> tuple[list[str], list[str], list[str]]:
    """Check if the command is an exact repeat of the last recorded command.

    Returns ``(errors, warnings, infos)`` tuples — compatible with GuardResult.add_* callers.
    """
    errors: list[str] = []
    warnings: list[str] = []
    infos: list[str] = []
    hist_path = _history_path(eng_dir)

    if not hist_path.exists():
        infos.append("history.md does not exist — will be recorded after command runs")
        return errors, warnings, infos

    content = hist_path.read_text(encoding="utf-8")
    lines = [line.strip() for line in content.splitlines() if line.strip()]

    if not lines:
        infos.append("history.md is empty — first command will be recorded")
        return errors, warnings, infos

    # History entries are written as ``... | command=<command>``. Compare
    # that field exactly instead of using substring matching, which can reject
    # a command merely because it contains the previous command text.
    last_line = lines[-1]
    recorded_command = _recorded_command(last_line)
    is_repeat = (recorded_command == command) or (
        recorded_command is not None
        and normalize_command(recorded_command) == normalize_command(command)
    )
    if is_repeat and not allow_pending_repeat:
        errors.append(
            f"command appears to be an exact repeat of the last recorded command: {last_line}"
        )
    elif is_repeat:
        infos.append("exact repeat belongs to the pending batch; allowing reconciliation/retry")

    return errors, warnings, infos


__all__ = [
    "normalize_command",
    "append_history",
    "history_contains",
    "check_history_staleness",
]
