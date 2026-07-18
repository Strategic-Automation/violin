"""PTT (Pentesting Task Tree) parsing, validation, and mutation.

Pure functions — no subprocess.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

from .phases import Phase, normalize_phase

__all__ = [
    "PttTask",
    "PttValidationResult",
    "parse_ptt",
    "validate_ptt",
    "find_active_task",
    "task_matches_phase",
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
            raw_phase = heading.group("phase").strip()
            # Human headings commonly add a parenthetical clarification.  The
            # phase token remains the first bare word, rather than becoming an
            # unmatchable value such as ``RECON_(WEB)``.
            raw_phase = re.split(r"\s*\(", raw_phase, maxsplit=1)[0].strip()
            try:
                current_phase = normalize_phase(raw_phase).value
            except ValueError:
                current_phase = raw_phase.upper().replace("-", "_").replace(" ", "_")
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


def create_task(path: Path, task_id: str, title: str, phase: str, note: str = "") -> PttTask:
    """Insert an explicitly requested untouched task into its canonical phase table."""
    if not re.fullmatch(r"PT-[\w-]+", task_id):
        raise ValueError("task id must use the PT- prefix")
    canonical_phase = normalize_phase(phase).value
    tasks = parse_ptt(path)
    if any(task.id == task_id for task in tasks):
        raise ValueError(f"PTT task {task_id!r} already exists")
    content = path.read_text(encoding="utf-8") if path.exists() else "# Pentesting Task Tree\n"
    lines = content.splitlines()
    phase_heading_index = None
    for index, line in enumerate(lines):
        match = re.match(r"^##\s+Phase:\s*(?P<phase>.+?)\s*$", line.strip(), re.IGNORECASE)
        if not match:
            continue
        raw_phase = re.split(r"\s*\(", match.group("phase"), maxsplit=1)[0].strip()
        try:
            heading_phase = normalize_phase(raw_phase).value
        except ValueError:
            continue
        if heading_phase == canonical_phase:
            phase_heading_index = index
            break

    if phase_heading_index is None:
        lines.extend(
            [
                "",
                f"## Phase: {canonical_phase}",
                "",
                "| ID | Status | Task | Notes |",
                "|---|---|---|---|",
            ]
        )
        phase_heading_index = len(lines) - 4

    next_heading_index = next(
        (
            index
            for index in range(phase_heading_index + 1, len(lines))
            if re.match(r"^##\s+Phase:", lines[index].strip(), re.IGNORECASE)
        ),
        len(lines),
    )
    table_start = next(
        (
            index
            for index in range(phase_heading_index + 1, next_heading_index)
            if lines[index].lstrip().startswith("|")
        ),
        None,
    )
    if table_start is None:
        raise ValueError(f"phase {canonical_phase} has no task table")

    table_end = table_start
    while table_end + 1 < next_heading_index and lines[table_end + 1].lstrip().startswith("|"):
        table_end += 1
    column_count = len([cell for cell in lines[table_start].strip().strip("|").split("|")])
    if column_count < 4:
        raise ValueError(f"phase {canonical_phase} task table must have at least four columns")

    def clean_cell(value: str) -> str:
        return value.strip().replace("|", "\\|").replace("\n", " ")

    cells = [task_id, "[ ]", clean_cell(title)]
    cells.extend([""] * (column_count - 4))
    cells.append(clean_cell(note))
    lines.insert(table_end + 1, "| " + " | ".join(cells) + " |")
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text("\n".join(lines) + "\n", encoding="utf-8")
    temporary.replace(path)
    return next(task for task in parse_ptt(path) if task.id == task_id)
