"""PTT (Pentesting Task Tree) parsing, validation, and mutation.

Pure functions — no subprocess.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from .phases import Phase, normalize_phase

__all__ = [
    "PttTask",
    "PttValidationResult",
    "parse_ptt",
    "validate_ptt",
    "find_active_task",
    "task_matches_phase",
    "is_stale",
    "update_task",
]


# | PT-001 | [ ] | Title | Note |
# Accepts PT-001 and PT-CTF-001 style ids; status tokens include the
# canonical blocked/dropped markers [!] and [-] (audit P0: CTF ids and the
# blocked/dropped states were previously rejected as "non-standard").
_PTT_RE = re.compile(
    r"^\|\s*(?P<id>PT-[\w-]+)\s*\|"
    r"\s*(?P<status>\[[ x~!-]\])\s*\|"
    r"\s*(?P<title>[^|]+?)\s*\|"
    r"\s*(?P<note>[^|]*?)\s*\|"
)

# Canonical status tokens the guard accepts without a warning.
_VALID_STATUSES = ("[ ]", "[~]", "[x]", "[!]", "[-]")


@dataclass
class PttTask:
    id: str
    status: str
    title: str
    note: str = ""
    updated: str = ""
    phase: str = ""

    def to_markdown(self) -> str:
        datetime.now(UTC).strftime("%Y-%m-%d %H:%M")
        return f"| {self.id} | {self.status} | {self.title} | {self.note} |"


@dataclass
class PttValidationResult:
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    tasks: list[PttTask] = field(default_factory=list)
    active_task: str | None = None

    def add_error(self, msg: str) -> None:
        self.errors.append(msg)

    def add_warning(self, msg: str) -> None:
        self.warnings.append(msg)

    def exit_code(self) -> int:
        if self.errors:
            return 1
        if self.warnings:
            return 2
        return 0


def parse_ptt(path: Path) -> list[PttTask]:
    """Parse PTT markdown file into list of PttTask."""
    if not path.exists():
        return []
    content = path.read_text(encoding="utf-8")
    tasks = []
    current_phase = ""
    for line in content.splitlines():
        heading = re.match(r"^##\s+Phase:\s*(?P<phase>.+?)\s*$", line.strip(), re.IGNORECASE)
        if heading:
            current_phase = (
                heading.group("phase").strip().upper().replace("-", "_").replace(" ", "_")
            )
            continue
        m = _PTT_RE.match(line.strip())
        if m:
            tasks.append(
                PttTask(
                    id=m.group("id").strip(),
                    status=m.group("status").strip(),
                    title=m.group("title").strip(),
                    note=m.group("note").strip(),
                    phase=current_phase,
                )
            )
    return tasks


def validate_ptt(tasks: list[PttTask]) -> PttValidationResult:
    """Validate PTT tasks."""
    result = PttValidationResult(tasks=tasks)
    active_count = 0
    seen_ids = set()

    for t in tasks:
        if t.id in seen_ids:
            result.add_error(f"duplicate task ID: {t.id}")
        seen_ids.add(t.id)

        if t.status == "[~]":
            active_count += 1
            result.active_task = t.id
        elif t.status not in _VALID_STATUSES:
            result.add_warning(f"{t.id}: non-standard status '{t.status}'")

        if not t.title.strip():
            result.add_error(f"{t.id}: empty title")

    if active_count == 0:
        result.add_error("no active task ([~]) — exactly one required")
    elif active_count > 1:
        result.add_error(f"multiple active tasks ({active_count}) — exactly one required")

    return result


def find_active_task(tasks: list[PttTask]) -> PttTask | None:
    """Return the single active task ([~]) or None."""
    for t in tasks:
        if t.status == "[~]":
            return t
    return None


def task_matches_phase(task: PttTask, phase: Phase | str) -> bool:
    """Whether a task belongs to the requested execution phase."""
    requested = normalize_phase(phase) if isinstance(phase, str) else phase
    expected = Phase.EXPLOITATION if requested is Phase.POST_EXPLOITATION else requested
    return task.phase == expected.value


def is_stale(path: Path) -> bool:
    """True if every task is still [ ] (pristine)."""
    tasks = parse_ptt(path)
    return all(t.status == "[ ]" for t in tasks) and len(tasks) > 0


def update_task(path: Path, task_id: str, status: str, note: str) -> PttTask:
    """Update a single PTT task row IN PLACE.

    The PTT is a human-authored document (prose, multiple tables, headings).
    This function rewrites only the matching row line and leaves every other
    line untouched (audit P0: the previous implementation flattened the whole
    document and could silently *create* a task to satisfy a caller). Creating
    a task is now a hard error — the guard must never invent tasks to unlock a
    batch.
    """
    status = status.strip()
    if status not in _VALID_STATUSES:
        raise ValueError(f"invalid PTT status {status!r}; expected one of {_VALID_STATUSES}")

    content = path.read_text(encoding="utf-8") if path.exists() else ""
    target_line = None
    target_idx = -1
    for i, line in enumerate(content.splitlines()):
        m = _PTT_RE.match(line.strip())
        if m and m.group("id").strip() == task_id:
            target_line = line
            target_idx = i
            break

    if target_line is None:
        raise ValueError(f"PTT task {task_id!r} not found; refusing to create it")

    cells = [c.strip() for c in target_line.strip().strip("|").split("|")]
    # cells: [id, status, title, note, ...]
    cells[1] = status
    if len(cells) >= 4:
        cells[-1] = note
    # Keep every original column. EXPLOITATION rows contain hypothesis,
    # validation-command, and patch columns that must not be flattened.
    new_line = "| " + " | ".join(cells) + " |"

    lines = content.splitlines()
    lines[target_idx] = new_line
    path.write_text(
        "\n".join(lines) + ("\n" if content and not content.endswith("\n") else ""),
        encoding="utf-8",
    )

    # Re-parse for a faithful return object.
    tasks = parse_ptt(path)
    for t in tasks:
        if t.id == task_id:
            return t
    raise RuntimeError(f"internal error: updated task {task_id!r} not found after rewrite")
