"""PTT (Pentesting Task Tree) parsing, validation, and mutation.

Pure functions — no subprocess.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

__all__ = [
    "PttTask",
    "PttValidationResult",
    "parse_ptt",
    "validate_ptt",
    "find_active_task",
    "is_stale",
    "update_task",
]


# | PT-001 | [ ] | Title | Note |
_PTT_RE = re.compile(
    r"^\|\s*(?P<id>PT-\d+)\s*\|\s*"
    r"(?P<status>\[[ x~]\])\s*\|\s*"
    r"(?P<title>[^|]+?)\s*\|\s*"
    r"(?P<note>[^|]*?)\s*\|"
)


@dataclass
class PttTask:
    id: str
    status: str
    title: str
    note: str = ""
    updated: str = ""

    def to_markdown(self) -> str:
        now = datetime.now(UTC).strftime("%Y-%m-%d %H:%M")
        ts = self.updated or now
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
    for line in content.splitlines():
        m = _PTT_RE.match(line.strip())
        if m:
            tasks.append(
                PttTask(
                    id=m.group("id").strip(),
                    status=m.group("status").strip(),
                    title=m.group("title").strip(),
                    note=m.group("note").strip(),
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
        elif t.status not in ("[ ]", "[x]"):
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


def is_stale(path: Path) -> bool:
    """True if every task is still [ ] (pristine)."""
    tasks = parse_ptt(path)
    return all(t.status == "[ ]" for t in tasks) and len(tasks) > 0


def update_task(path: Path, task_id: str, status: str, note: str) -> PttTask:
    """Update a task in the PTT file (creates if missing)."""
    tasks = parse_ptt(path)
    target = None
    for t in tasks:
        if t.id == task_id:
            target = t
            break

    if target is None:
        target = PttTask(id=task_id, status=status, title=f"Task {task_id}", note=note)
        tasks.append(target)
    else:
        target.status = status
        target.note = note

    target.updated = datetime.now(UTC).strftime("%Y-%m-%d %H:%M")
    _rewrite_ptt(path, tasks)
    return target


def _rewrite_ptt(path: Path, tasks: list[PttTask]) -> None:
    """Rewrite the entire PTT file."""
    path.parent.mkdir(parents=True, exist_ok=True)

    # Read existing to preserve header
    header = ""
    if path.exists():
        content = path.read_text(encoding="utf-8")
        # Find first task line
        first_task = content.find("| PT-")
        if first_task != -1:
            header = content[:first_task].rstrip() + "\n"
        else:
            header = "# PTT\n\n"

    # Ensure standard header
    if "PTT" not in header:
        header = "# Pentesting Task Tree (PTT)\n\n| ID | Status | Title | Note |\n|----|--------|-------|------|\n"

    body = "\n".join(t.to_markdown() for t in tasks)
    path.write_text(header + body + "\n", encoding="utf-8")