"""PTT (Pentesting Task Tree) parsing, validation, and mutation.

Pure functions — no subprocess.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

from .markdown_structure import MarkdownBlock, iter_markdown_blocks, read_markdown
from .phases import Phase, normalize_phase
from .results import GuardResult
from .state import atomic_text

__all__ = [
    "PttTask",
    "PttValidationResult",
    "parse_ptt",
    "validate_ptt",
    "find_active_task",
    "task_matches_phase",
    "update_task",
    "update_tasks",
    "sync_ptt",
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
_PAREN_SPLIT_RE = re.compile(r"\s*\(")
_TASK_ID_RE = re.compile(r"PT-[\w-]+")

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
        # Composition preserves the existing positional fields and serialized shape.
        return GuardResult(errors=self.errors, warnings=self.warnings).exit_code()


def parse_ptt(path: Path) -> list[PttTask]:
    """Parse task rows from pipe tables inside recognized phase sections."""
    if not path.exists():
        return []
    return [task for task, _line_index in _ptt_rows(read_markdown(path))]


def _phase_from_heading(heading_text: str, level: int) -> str | None:
    if level != 2 or not heading_text.casefold().startswith("phase:"):
        return None
    raw_phase = heading_text.partition(":")[2].strip()
    raw_phase = _PAREN_SPLIT_RE.split(raw_phase, maxsplit=1)[0].strip()
    try:
        return normalize_phase(raw_phase).value
    except ValueError:
        return raw_phase.upper().replace("-", "_").replace(" ", "_")


def _phase_tables(
    blocks: list[MarkdownBlock], lines: list[str]
) -> tuple[tuple[str, int, int], ...]:
    """Return real Markdown tables associated with their nearest level-two phase."""
    phase_tables: list[tuple[str, int, int]] = []
    phase_headings = [block for block in blocks if block.kind == "heading" and block.level <= 2]
    for table in (block for block in blocks if block.kind == "table"):
        table_start, table_end = table.start, table.end
        if not _is_task_table(lines, table_start, table_end):
            continue
        previous = next(
            (heading for heading in reversed(phase_headings) if heading.start < table_start),
            None,
        )
        if previous is None:
            continue
        phase = _phase_from_heading(previous.text, previous.level)
        if phase:
            phase_tables.append((phase, table_start, table_end))
    return tuple(phase_tables)


def _pipe_cells(line: str) -> list[str]:
    separators = _pipe_positions(line)
    if len(separators) < 2:
        return []
    return [
        line[start + 1 : end].strip()
        for start, end in zip(separators, separators[1:], strict=False)
    ]


def _is_task_table(lines: list[str], start: int, end: int) -> bool:
    if end - start < 2 or start + 1 >= len(lines):
        return False
    headers = [cell.casefold() for cell in _pipe_cells(lines[start])]
    divider = _pipe_cells(lines[start + 1])
    return (
        len(headers) >= 4
        and headers[:3] == ["id", "status", "task"]
        and all(re.fullmatch(r":?-{3,}:?", cell) for cell in divider)
        and len(divider) == len(headers)
    )


def _ptt_rows(source: str) -> list[tuple[PttTask, int]]:
    blocks = list(iter_markdown_blocks(source))
    protected = [(block.start, block.end) for block in blocks if block.kind == "protected"]
    lines = source.splitlines()
    rows: list[tuple[PttTask, int]] = []
    for phase, start, end in _phase_tables(blocks, lines):
        for line_index in range(start, min(end, len(lines))):
            if any(start <= line_index < end for start, end in protected):
                continue
            match = _PTT_RE.match(lines[line_index].strip())
            if match:
                rows.append(
                    (
                        PttTask(
                            id=match.group("id").strip(),
                            status=match.group("status").strip(),
                            title=match.group("title").strip(),
                            note=match.group("note").strip(),
                            phase=phase,
                        ),
                        line_index,
                    )
                )
    return rows


def validate_ptt(tasks: list[PttTask]) -> PttValidationResult:
    """Validate PTT tasks."""
    result = PttValidationResult(tasks=tasks)
    active_count = 0
    seen_ids = set()

    for task in tasks:
        if task.id in seen_ids:
            result.add_error(f"duplicate task ID: {task.id}")
        seen_ids.add(task.id)

        if task.status == "[~]":
            active_count += 1
            result.active_task = task.id
        elif task.status not in _VALID_STATUSES:
            result.add_warning(f"{task.id}: non-standard status '{task.status}'")

        if not task.title.strip():
            result.add_error(f"{task.id}: empty title")

    if active_count == 0:
        result.add_error(
            "no active task ([~]) — exactly one required; use violin_record_ptt to open or reuse one"
        )
    elif active_count > 1:
        result.add_error(f"multiple active tasks ({active_count}) — exactly one required")

    return result


def find_active_task(tasks: list[PttTask]) -> PttTask | None:
    """Return the single active task ([~]) or None."""
    for task in tasks:
        if task.status == "[~]":
            return task
    return None


def task_matches_phase(task: PttTask, phase: Phase | str) -> bool:
    """Whether a task belongs to the requested execution phase."""
    requested = normalize_phase(phase) if isinstance(phase, str) else phase
    expected = Phase.EXPLOITATION if requested is Phase.POST_EXPLOITATION else requested
    return task.phase == expected.value


def update_tasks(path: Path, updates: dict[str, tuple[str, str]]) -> dict[str, PttTask]:
    """Validate and atomically apply one or more task-row updates.

    The PTT is a human-authored document (prose, multiple tables, headings).
    This function rewrites only matching row lines and leaves every other
    line untouched (audit P0: the previous implementation flattened the whole
    document). Every target and status is validated before the atomic replace.
    """
    normalized: dict[str, tuple[str, str]] = {}
    for task_id, (status, note) in updates.items():
        status = status.strip()
        if status not in _VALID_STATUSES:
            raise ValueError(f"invalid PTT status {status!r}; expected one of {_VALID_STATUSES}")
        normalized[task_id] = (status, note)

    content = read_markdown(path) if path.exists() else ""
    lines = content.splitlines(keepends=True)
    row_indices: dict[str, int] = {}
    for task, line_index in _ptt_rows(content):
        if task.id in normalized:
            if task.id in row_indices:
                raise ValueError(f"PTT task {task.id!r} appears in more than one phase table")
            row_indices[task.id] = line_index

    missing = sorted(set(normalized) - set(row_indices))
    if missing:
        raise ValueError(f"PTT task {missing[0]!r} not found; refusing to create it")

    for task_id, target_idx in row_indices.items():
        status, note = normalized[task_id]
        lines[target_idx] = _replace_task_row(lines[target_idx], status, note)

    atomic_text(path, "".join(lines))
    tasks = sync_ptt(path)
    result = {task.id: task for task in tasks if task.id in normalized}
    if len(result) != len(normalized):
        raise RuntimeError("internal error: updated PTT tasks were not found after rewrite")
    return result


def _pipe_positions(line: str) -> list[int]:
    positions: list[int] = []
    backslashes = 0
    for index, character in enumerate(line):
        if character == "|" and backslashes % 2 == 0:
            positions.append(index)
        if character == "\\":
            backslashes += 1
        else:
            backslashes = 0
    return positions


def _replace_pipe_cell(line: str, cell_index: int, value: str) -> str:
    separators = _pipe_positions(line)
    if len(separators) < 5 or cell_index >= len(separators) - 1:
        raise ValueError("PTT row must contain an ID, status, task, and notes column")
    cell_start = separators[cell_index] + 1
    cell_end = separators[cell_index + 1]
    while cell_start < cell_end and line[cell_start].isspace():
        cell_start += 1
    while cell_end > cell_start and line[cell_end - 1].isspace():
        cell_end -= 1
    return line[:cell_start] + value + line[cell_end:]


def _replace_task_row(line: str, status: str, note: str) -> str:
    """Replace the status and final notes cell without reformatting other source."""
    separators = _pipe_positions(line)
    cell_count = len(separators) - 1
    if cell_count < 4:
        raise ValueError("PTT row must contain at least four columns")
    updated = _replace_pipe_cell(line, 1, status)
    return _replace_pipe_cell(updated, cell_count - 1, note.replace("|", "\\|"))


def update_task(path: Path, task_id: str, status: str, note: str) -> PttTask:
    """Validate and atomically update one PTT task row."""
    return update_tasks(path, {task_id: (status, note)})[task_id]


def create_task(path: Path, task_id: str, title: str, phase: str, note: str = "") -> PttTask:
    """Insert an explicitly requested untouched task into its canonical phase table."""
    if not _TASK_ID_RE.fullmatch(task_id):
        raise ValueError("task id must use the PT- prefix")
    canonical_phase = normalize_phase(phase).value
    tasks = parse_ptt(path)
    if any(task.id == task_id for task in tasks):
        raise ValueError(f"PTT task {task_id!r} already exists")
    content = read_markdown(path) if path.exists() else "# Pentesting Task Tree\n"
    blocks = list(iter_markdown_blocks(content))
    phase_heading = next(
        (
            heading
            for heading in blocks
            if heading.kind == "heading"
            and heading.level == 2
            and _phase_from_heading(heading.text, heading.level) == canonical_phase
        ),
        None,
    )
    tables = [
        (start, end)
        for table_phase, start, end in _phase_tables(blocks, content.splitlines())
        if table_phase == canonical_phase
    ]
    if phase_heading is None:
        newline = "\r\n" if "\r\n" in content else "\n"
        clean_title = title.strip().replace("|", "\\|").replace("\n", " ")
        clean_note = note.strip().replace("|", "\\|").replace("\n", " ")
        separator = ""
        if content and not content.endswith(newline + newline):
            separator = newline if content.endswith(newline) else newline + newline
        addition = (
            separator
            + f"## Phase: {canonical_phase}{newline}{newline}"
            + "| ID | Status | Task | Notes |"
            + newline
            + "|---|---|---|---|"
            + newline
            + f"| {task_id} | [ ] | {clean_title} | {clean_note} |"
            + newline
        )
        atomic_text(path, content + addition)
        sync_ptt(path)
        return next(task for task in parse_ptt(path) if task.id == task_id)
    if len(tables) != 1:
        raise ValueError(f"phase {canonical_phase} must contain exactly one Markdown task table")

    lines = content.splitlines(keepends=True)
    table_start, table_end = tables[0]
    header_line = lines[table_start]
    column_count = len(_pipe_positions(header_line)) - 1
    if column_count < 4:
        raise ValueError(f"phase {canonical_phase} task table must have at least four columns")

    def clean_cell(value: str) -> str:
        return value.strip().replace("|", "\\|").replace("\n", " ")

    cells = [task_id, "[ ]", clean_cell(title)]
    cells.extend([""] * (column_count - 4))
    cells.append(clean_cell(note))
    newline = "\r\n" if "\r\n" in content else "\n"
    if table_end > 0 and not lines[table_end - 1].endswith(("\n", "\r")):
        lines[table_end - 1] += newline
    lines.insert(table_end, "| " + " | ".join(cells) + " |" + newline)
    atomic_text(path, "".join(lines))
    sync_ptt(path)
    return next(task for task in parse_ptt(path) if task.id == task_id)


def sync_ptt(path: Path) -> list[PttTask]:
    """Synchronize top-level summary checklist items (- [ ] PT-XXX) with table row statuses."""
    if not path.exists():
        return []
    tasks = parse_ptt(path)
    if not tasks:
        return []
    task_statuses = {task.id: task.status for task in tasks}

    content = read_markdown(path)
    lines = content.splitlines(keepends=True)
    blocks = list(iter_markdown_blocks(content))
    summary_end = min(
        (heading.start for heading in blocks if heading.kind == "heading" and heading.level >= 2),
        default=len(lines),
    )
    modified = False

    bullet_re = re.compile(
        r"^(?P<prefix>\s*-\s*)(?P<status>\[[ x~!-]\])(?P<rest>\s+(?P<id>PT-[\w-]+)\b.*)"
    )
    for i, line in enumerate(lines[:summary_end]):
        if any(block.kind == "protected" and block.start <= i < block.end for block in blocks):
            continue
        m = bullet_re.match(line)
        if m:
            t_id = m.group("id")
            if t_id in task_statuses:
                new_status = task_statuses[t_id]
                status_start = m.start("status")
                status_end = m.end("status")
                new_line = line[:status_start] + new_status + line[status_end:]
                if new_line != line:
                    lines[i] = new_line
                    modified = True

    if modified:
        atomic_text(path, "".join(lines))
        tasks = parse_ptt(path)
    return tasks
