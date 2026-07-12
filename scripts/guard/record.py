"""PTT/history record and staleness guards for the Violin guard package."""

from __future__ import annotations

import argparse
import re
from datetime import UTC, datetime
from pathlib import Path

from guard.core import CheckResult

# Valid status markers in the PTT (must match templates/ptt.md §Task State Legend)
VALID_STATUSES = {"[ ]", "[~]", "[x]", "[!]", "[-]"}
# Regex for a PTT row: | PT-016 | [ ] | task text | evidence |
_PTT_ROW_RE = re.compile(r"^(\|\s*)(PT-\d+)(\s*\|\s*)\[( |~|x|!|-)\](\s*\|)", re.MULTILINE)


def _find_ptt_row(lines: list[str], pt_id: str) -> tuple[int, re.Match] | None:
    """Locate the PTT row for the given PT-XXX id. Returns (line_index, match)."""
    for idx, line in enumerate(lines):
        m = _PTT_ROW_RE.match(line)
        if m and m.group(2) == pt_id:
            return idx, m
    return None


# Phase inference from PT-XXX numeric prefix (matches ptt.md ID ranges).
_PHASE_PREFIX_RANGES = [
    ("SCOPING", 1, 9),
    ("RECON", 10, 29),
    ("VULN RESEARCH", 30, 39),
    ("EXPLOITATION", 40, 49),
    ("REPORTING", 50, 59),
    ("RETROSPECTIVE", 60, 69),
]
# Special section for out-of-range / ad-hoc ids (template already ships it).
_BLOCKED_SECTION = "BLOCKED"  # -> "## Blocked / Deferred Tasks"

# Default table headers per section (used when a phase section must be created).
_DEFAULT_PHASE_HEADERS = {
    "EXPLOITATION": "| ID | Status | Task | Hypothesis | Validation Cmd | Auto-Patch | Evidence / Notes |",
    "BLOCKED": "| ID | Status | Task | Reason | Resolution Path |",
}
_DEFAULT_PHASE_HEADER = "| ID | Status | Task | Evidence / Notes |"


def _infer_phase(pt_id: str) -> str:
    """Map a PT-XXX id to its phase section name (or BLOCKED for out-of-range)."""
    num = int(pt_id.split("-")[1])
    for name, lo, hi in _PHASE_PREFIX_RANGES:
        if lo <= num <= hi:
            return name
    return _BLOCKED_SECTION


def _section_header_for(phase: str) -> str:
    return "## Blocked / Deferred Tasks" if phase == _BLOCKED_SECTION else f"## Phase: {phase}"


def _phase_data_cols(header_line: str) -> int:
    """Count data columns in a markdown table header row."""
    return len(header_line.split("|")[1:-1])


def _ensure_phase_section(lines: list[str], phase: str) -> tuple[int, int]:
    """Return (insert_index, data_cols) for a new row in ``phase``.

    If the section does not exist, it is created (with a default header) at a
    sensible location: immediately before ``## Blocked / Deferred Tasks`` if
    present, otherwise before the ``*Last updated`` footer, otherwise appended
    at the end. The returned index is where the new data row should be inserted.
    """
    phase = phase.upper()
    header_target = _section_header_for(phase)

    # 1) Existing section?
    for i, line in enumerate(lines):
        if line.strip().startswith(header_target):
            header_idx = None
            for j in range(i + 1, min(i + 6, len(lines))):
                if lines[j].lstrip().startswith("|") and "ID" in lines[j]:
                    header_idx = j
                    break
            if header_idx is None:
                break
            data_cols = _phase_data_cols(lines[header_idx])
            # The table header separator is a `|----|` row; the section-closing
            # separator is a bare `---` line. Insert the new row *inside* the
            # table, just before the section-closing `---` (falling back to the
            # end of the table body if no closing `---` exists).
            header_sep_idx = None
            close_sep_idx = None
            for j in range(header_idx + 1, len(lines)):
                if header_sep_idx is None and lines[j].lstrip().startswith("|----"):
                    header_sep_idx = j
                elif header_sep_idx is not None and lines[j].strip() == "---":
                    close_sep_idx = j
                    break
            if close_sep_idx is not None:
                insert_idx = close_sep_idx
            elif header_sep_idx is not None:
                # No closing `---`: insert after the last table body row.
                insert_idx = header_sep_idx + 1
                while insert_idx < len(lines) and (
                    lines[insert_idx].lstrip().startswith("|") or lines[insert_idx].strip() == ""
                ):
                    insert_idx += 1
            else:
                insert_idx = header_idx + 1
            return insert_idx, data_cols

    # 2) Create the section.
    default_header = _DEFAULT_PHASE_HEADERS.get(phase, _DEFAULT_PHASE_HEADER)
    data_cols = _phase_data_cols(default_header)
    sep = "|" + "---|" * data_cols
    block = [header_target + "\n", "\n", default_header + "\n", sep + "\n"]

    # Insert before "## Blocked / Deferred Tasks", else before footer, else append.
    pos = len(lines)
    for i, line in enumerate(lines):
        if line.strip().startswith("## Blocked / Deferred Tasks"):
            pos = i
            break
    else:
        for i, line in enumerate(lines):
            if line.lstrip().startswith("*Last updated"):
                pos = i
                break
    lines[pos:pos] = block
    # New row goes right after the separator line we just inserted.
    return pos + len(block), data_cols


def _list_phases_and_next_ids(lines: list[str]) -> str:
    """Build a helpful hint listing phases and the next free PT id per phase."""
    hints = []
    for name, lo, hi in _PHASE_PREFIX_RANGES:
        used = set()
        for line in lines:
            m = _PTT_ROW_RE.match(line)
            if m and lo <= int(m.group(2).split("-")[1]) <= hi:
                used.add(int(m.group(2).split("-")[1]))
        nxt = next((n for n in range(lo, hi + 1) if n not in used), None)
        span = f"{lo:03d}-{hi:03d}"
        hints.append(
            f"{name} (PT-{span})" + (f" -> next free: PT-{nxt:03d}" if nxt else " -> full")
        )
    return "; ".join(hints)


def _ptt_is_stale(ptt_path: Path) -> bool:
    """A PTT is 'stale' if every PT-XXX row is still in the pristine [ ] state
    (i.e. no task has ever been touched). Used by check-bootstrap at session
    resume to surface drift."""
    if not ptt_path.exists() or not ptt_path.is_file():
        return False
    text = ptt_path.read_text(encoding="utf-8")
    rows = _PTT_ROW_RE.findall(text)
    if not rows:
        return False
    # rows is a list of tuples; group(4) is the status char (space, ~, x, !, -)
    return all(m[3] == " " for m in rows)


def record_ptt(args: argparse.Namespace) -> int:
    """Update or create a PT-XXX row in the PTT.

    Status update mode (default): change an existing row's status marker and
    append a note to the Evidence / Notes column.

    Create mode (``--create``): insert a brand-new task row. Used when the
    requested PT-XXX id is not present in the PTT (e.g. a freshly discovered
    task like PT-070 that falls outside the bootstrap template). The phase is
    inferred from the PT-XXX numeric prefix unless ``--phase`` is given, and
    the target section is created on the fly if missing. Requires ``--task``.

    Required: --eng-dir, --id (PT-XXX)
    Status mode also requires: --status (one of [ ] [~] [x] [!] [-])
    Create mode also requires: --create and --task "<task text>"
    Optional: --note, --phase (override inference), --evidence "<path/notes>"

    Exit codes:
      0 = row updated or created
      1 = PTT missing, invalid id/status, missing --task in create mode,
          or other failure
    """
    result = CheckResult()
    eng_dir = Path(args.eng_dir or "")
    ptt_path = eng_dir / "state" / "ptt.md"
    create = bool(getattr(args, "create", False))
    pt_id = (args.id or "").strip().upper()
    # Keep None distinct (so --create without --status defaults to [ ]) by not
    # collapsing via `or ""` here; only strip when a value was supplied.
    new_status_raw = (args.status or "").strip() if getattr(args, "status", None) else None
    note = (args.note or "").strip()
    task_text = (args.task or "").strip()
    phase_override = (getattr(args, "phase", "") or "").strip().upper()

    if not eng_dir.exists():
        result.add_error(f"engagement directory not found: {eng_dir}")
        result.print()
        return 1
    if not ptt_path.exists() or not ptt_path.is_file():
        result.add_error(f"PTT not found (or is a directory): {ptt_path}")
        result.add_info(
            'bootstrap with: cp skills/pentest/templates/ptt.md "$ENG_DIR/state/ptt.md"'
        )
        result.print()
        return 1
    if not re.fullmatch(r"PT-\d+", pt_id):
        result.add_error(f"--id must be a PT-XXX identifier (e.g. PT-016), got: {args.id!r}")
        result.print()
        return 1

    # Normalize status: accept with or without brackets, convert to bracketed form
    status_char_map = {" ": "[ ]", "~": "[~]", "x": "[x]", "!": "[!]", "-": "[-]"}
    if new_status_raw is None:
        # Omitted: allowed only in --create mode (defaults to Open). In status
        # update mode the id would be present, so require an explicit --status.
        new_status = "[ ]"
    elif new_status_raw in VALID_STATUSES:
        new_status = new_status_raw
    elif new_status_raw in status_char_map:
        new_status = status_char_map[new_status_raw]
    elif len(new_status_raw) == 1 and new_status_raw in " ~x!-":
        # Single char like 'x', '~', ' ', '!', '-'
        new_status = status_char_map.get(new_status_raw, new_status_raw)
    else:
        result.add_error(
            f"--status must be one of {sorted(VALID_STATUSES)} (e.g. '[x]', 'x', '[~]', '~'), got: {new_status_raw!r}"
        )
        result.print()
        return 1

    lines = ptt_path.read_text(encoding="utf-8").splitlines(keepends=True)
    located = _find_ptt_row(lines, pt_id)

    # ---- Create mode: id not present -> create the row + section ----------
    if located is None:
        if not create:
            result.add_error(f"PT-XXX id {pt_id} not found in {ptt_path}")
            result.add_info(
                'to add a new task row, re-run with --create --task "<task text>" '
                "(phase auto-inferred from the id; or pass --phase <PHASE>)"
            )
            result.add_info("phases: " + _list_phases_and_next_ids(lines))
            result.print()
            return 1
        if not task_text:
            result.add_error('--create requires --task "<task text>" for the new row')
            result.print()
            return 1
        phase = phase_override or _infer_phase(pt_id)
        insert_idx, data_cols = _ensure_phase_section(lines, phase)
        # If a "(none yet)" placeholder row exists in this section, replace it
        # directly with the new row so no stray blank line is left behind.
        replace_idx = None
        for k in range(insert_idx - 1, -1, -1):
            if lines[k].strip().startswith("---"):
                break
            if "| (none yet)" in lines[k]:
                replace_idx = k
                break
        # Build a new row with the right number of data columns.
        initial_status = new_status
        cells = [pt_id, initial_status, task_text]
        if note:
            cells.append(note)
        while len(cells) < data_cols:
            cells.append("—")
        # Truncate if more cells than columns (keep id, status, task, note, ...).
        if len(cells) > data_cols:
            cells = cells[:2] + [" ".join(cells[2:])] if data_cols >= 3 else cells[:data_cols]
        new_row = "| " + " | ".join(cells) + " |\n"
        if replace_idx is not None:
            lines[replace_idx] = new_row
        else:
            lines.insert(insert_idx, new_row)
        # Bump the "Last updated:" footer.
        now = datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC")
        for i, line in enumerate(lines):
            if line.lstrip().startswith("*Last updated"):
                lines[i] = f"*Last updated: {now}*\n"
                break
        ptt_path.write_text("".join(lines), encoding="utf-8")
        result.add_info(
            f"PTT {pt_id} CREATED in {phase} phase" + (f" — {task_text}" if task_text else "")
        )
        result.print()
        return 0

    # ---- Status-update mode: id present --------------------------------
    idx, m = located
    old_marker = f"[{m.group(4)}]"
    # Replace the status marker in place
    new_char = new_status[1]  # strip brackets, keep the inner char
    rebuilt = m.group(1) + pt_id + m.group(3) + f"[{new_char}]" + m.group(5)
    # Preserve the rest of the line (task text + evidence columns)
    rest_of_line = lines[idx][m.end() :]
    lines[idx] = rebuilt + rest_of_line

    # If a note was provided, append it to the Evidence / Notes column.
    # We keep everything up to the last "|", then append " — <note>"
    # before the closing pipe so successive updates chain.
    if note:
        raw = lines[idx]
        eol = "\r\n" if raw.endswith("\r\n") else "\n" if raw.endswith("\n") else ""
        body = raw.rstrip("\r\n")

        last_pipe = body.rfind("|")
        if last_pipe > 0:
            existing = body[:last_pipe].rstrip()
            sep = " — " if existing and not existing.endswith(" — ") else ""
            lines[idx] = existing + sep + note + body[last_pipe:] + eol

    # Bump the "Last updated:" footer (last non-empty line starting with *Last updated)
    now = datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC")
    for i, line in enumerate(lines):
        if line.lstrip().startswith("*Last updated"):
            lines[i] = f"*Last updated: {now}*\n"
            break

    ptt_path.write_text("".join(lines), encoding="utf-8")
    result.add_info(
        f"PTT {pt_id} status: {old_marker} → {new_status}" + (f" — {note}" if note else "")
    )
    result.print()
    return 0


def record_history(args: argparse.Namespace) -> int:
    """Append a timestamped entry to $ENG_DIR/state/history.md.

    Required: --eng-dir, --command (the shell command that ran), --exit-code (int)
    Optional: --phase (defaults to UNKNOWN), --evidence (path under $ENG_DIR/evidence/)

    Exit codes:
      0 = entry appended
      1 = history.md missing or --command empty
    """
    result = CheckResult()
    eng_dir = Path(args.eng_dir or "")
    history_path = eng_dir / "state" / "history.md"
    command = (args.command or "").strip()
    phase = (args.phase or "UNKNOWN").strip().upper()
    evidence = (args.evidence or "").strip()
    exit_code = args.exit_code

    if not eng_dir.exists():
        result.add_error(f"engagement directory not found: {eng_dir}")
        result.print()
        return 1
    if not history_path.exists() or not history_path.is_file():
        result.add_error(f"history.md not found (or is a directory): {history_path}")
        result.add_info(
            'initialise with: echo "# Command History — $(date +%F)" > "$ENG_DIR/state/history.md"'
        )
        result.print()
        return 1
    if not command:
        result.add_error("--command is required (the shell command that was just run)")
        result.print()
        return 1

    ts = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    entry = f"- [{ts}] [{phase}] exit={exit_code}"
    if evidence:
        entry += f" evidence={evidence}"
    # Escape any embedded newlines in the command so the table stays one-line-per-entry
    safe_cmd = command.replace("\n", " ⏎ ")
    entry += f" `{safe_cmd}`\n"

    with history_path.open("a", encoding="utf-8") as fh:
        fh.write(entry)

    result.add_info(
        f"history appended: [{phase}] exit={exit_code} `{safe_cmd[:60]}{'…' if len(safe_cmd) > 60 else ''}`"
    )
    result.print()
    return 0


def _ptt_staleness_guard(ptt_path: Path, history_path: Path | None = None) -> CheckResult:
    result = CheckResult()
    if not ptt_path.exists() or not ptt_path.is_file():
        result.add_error(f"PTT missing: {ptt_path}")
        result.add_info(
            'bootstrap with: cp skills/pentest/templates/ptt.md "$ENG_DIR/state/ptt.md"'
        )
        return result
    if _ptt_is_stale(ptt_path):
        # On a fresh engagement, the first command necessarily runs before the
        # executor can append its history record. Requiring a PTT transition at
        # this point creates a bootstrap deadlock: the task must look started
        # before any work has actually happened. Keep the exception narrow: as
        # soon as history contains a recorded command, normal PTT enforcement
        # resumes.
        if history_path is not None and history_path.is_file():
            history = history_path.read_text(encoding="utf-8")
            if not re.findall(r"`([^`]+)`", history):
                result.add_info(
                    "PTT is pristine; the first command may run before task progress is recorded"
                )
                return result
        result.add_error("PTT is stale: no PT-XXX row has moved past [ ]; update before advancing")
        result.add_info(
            'run: python scripts/violin_guard.py record-ptt --eng-dir "$ENG_DIR" --id <PT-XXX> --status [~] --note "<batch result>"'
        )
    return result


def _history_staleness_guard(eng_dir: Path, lowered_command: str) -> CheckResult:
    result = CheckResult()
    history_path = eng_dir / "state" / "history.md"
    if not history_path.exists() or not history_path.is_file():
        result.add_error(f"history.md missing: {history_path}")
        result.add_info(
            'initialise with: echo "# Command History — $(date +%F)" > "$ENG_DIR/state/history.md"'
        )
        return result
    text = history_path.read_text(encoding="utf-8")
    backtick_commands = re.findall(r"`([^`]+)`", text)
    if not backtick_commands:
        # Fresh bootstrap: the enforced executor records the command after the
        # process exits. This must be informational rather than REVIEW; in
        # manual mode REVIEW prevents execution and would deadlock the first
        # command by demanding history before the command can run.
        result.add_info("history.md is empty; this command will be recorded after it runs")
        return result
    # NOTE (root-cause fix, issue 2): the single exact-repeat "duplicate
    # command" warning was removed. It fired on *every* re-issue of a command
    # the agent had legitimately just run + synced, forcing a
    # REVIEW -> sync -> REVIEW loop that blocked non-interactive / yolo sessions.
    # Genuine retry loops are still caught by the hard anti-stuck block in
    # sync.py (repeat_count >= RETRY_LIMIT) which BLOCKs after 3+ identical
    # re-issues without progress.
    return result
