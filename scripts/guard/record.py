"""PTT/history record and staleness guards for the Violin guard package."""

from __future__ import annotations

import argparse
import re
from datetime import datetime, timezone
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
    """Update a PT-XXX row in the PTT: change its status marker and append a
    note to the Evidence / Notes column. Also bumps the 'Last updated' footer.

    Required: --eng-dir, --id (PT-XXX), --status (one of [ ] [~] [x] [!] [-])
    Optional: --note (one-line result; appended to the Evidence column)

    Exit codes:
      0 = row updated
      1 = PTT missing, PT-XXX not found, or invalid status marker
    """
    result = CheckResult()
    eng_dir = Path(args.eng_dir or "")
    ptt_path = eng_dir / "state" / "ptt.md"
    pt_id = (args.id or "").strip().upper()
    new_status_raw = (args.status or "").strip()
    note = (args.note or "").strip()

    if not eng_dir.exists():
        result.add_error(f"engagement directory not found: {eng_dir}")
        result.print()
        return 1
    if not ptt_path.exists() or not ptt_path.is_file():
        result.add_error(f"PTT not found (or is a directory): {ptt_path}")
        result.add_info("bootstrap with: cp skills/pentest/templates/ptt.md \"$ENG_DIR/state/ptt.md\"")
        result.print()
        return 1
    if not re.fullmatch(r"PT-\d+", pt_id):
        result.add_error(f"--id must be a PT-XXX identifier (e.g. PT-016), got: {args.id!r}")
        result.print()
        return 1
    
    # Normalize status: accept with or without brackets, convert to bracketed form
    status_char_map = {" ": "[ ]", "~": "[~]", "x": "[x]", "!": "[!]", "-": "[-]"}
    if new_status_raw in VALID_STATUSES:
        new_status = new_status_raw
    elif new_status_raw in status_char_map:
        new_status = status_char_map[new_status_raw]
    elif len(new_status_raw) == 1 and new_status_raw in " ~x!-":
        # Single char like 'x', '~', ' ', '!', '-'
        new_status = status_char_map.get(new_status_raw, new_status_raw)
    else:
        result.add_error(f"--status must be one of {sorted(VALID_STATUSES)} (e.g. '[x]', 'x', '[~]', '~'), got: {new_status_raw!r}")
        result.print()
        return 1

    lines = ptt_path.read_text(encoding="utf-8").splitlines(keepends=True)
    located = _find_ptt_row(lines, pt_id)
    if located is None:
        result.add_error(f"PT-XXX id {pt_id} not found in {ptt_path}")
        result.add_info("open the PTT and verify the id exists in the current phase table")
        result.print()
        return 1

    idx, m = located
    old_marker = f"[{m.group(4)}]"
    # Replace the status marker in place
    new_char = new_status[1]  # strip brackets, keep the inner char
    rebuilt = (
        m.group(1) + pt_id + m.group(3) + f"[{new_char}]" + m.group(5)
    )
    # Preserve the rest of the line (task text + evidence columns)
    rest_of_line = lines[idx][m.end():]
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
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    for i, line in enumerate(lines):
        if line.lstrip().startswith("*Last updated"):
            lines[i] = f"*Last updated: {now}*\n"
            break

    ptt_path.write_text("".join(lines), encoding="utf-8")
    result.add_info(f"PTT {pt_id} status: {old_marker} → {new_status}" + (f" — {note}" if note else ""))
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
        result.add_info('initialise with: echo "# Command History — $(date +%F)" > "$ENG_DIR/state/history.md"')
        result.print()
        return 1
    if not command:
        result.add_error("--command is required (the shell command that was just run)")
        result.print()
        return 1

    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    entry = f"- [{ts}] [{phase}] exit={exit_code}"
    if evidence:
        entry += f" evidence={evidence}"
    # Escape any embedded newlines in the command so the table stays one-line-per-entry
    safe_cmd = command.replace("\n", " ⏎ ")
    entry += f" `{safe_cmd}`\n"

    with history_path.open("a", encoding="utf-8") as fh:
        fh.write(entry)

    result.add_info(f"history appended: [{phase}] exit={exit_code} `{safe_cmd[:60]}{'…' if len(safe_cmd) > 60 else ''}`")
    result.print()
    return 0


def _ptt_staleness_guard(ptt_path: Path) -> CheckResult:
    result = CheckResult()
    if not ptt_path.exists() or not ptt_path.is_file():
        result.add_error(f"PTT missing: {ptt_path}")
        result.add_info("bootstrap with: cp skills/pentest/templates/ptt.md \"$ENG_DIR/state/ptt.md\"")
        return result
    if _ptt_is_stale(ptt_path):
        result.add_error("PTT is stale: no PT-XXX row has moved past [ ]; update before advancing")
        result.add_info("run: python scripts/violin_guard.py record-ptt --eng-dir \"$ENG_DIR\" --id <PT-XXX> --status [~] --note \"<batch result>\"")
    return result


def _history_staleness_guard(eng_dir: Path, lowered_command: str) -> CheckResult:
    result = CheckResult()
    history_path = eng_dir / "state" / "history.md"
    if not history_path.exists() or not history_path.is_file():
        result.add_error(f"history.md missing: {history_path}")
        result.add_info('initialise with: echo "# Command History — $(date +%F)" > "$ENG_DIR/state/history.md"')
        return result
    text = history_path.read_text(encoding="utf-8")
    backtick_commands = re.findall(r"`([^`]+)`", text)
    if not backtick_commands:
        # No commands recorded yet (fresh bootstrap). Soft warning, not a block,
        # so the first target command after bootstrap is not hard-stopped.
        result.add_warning("history.md has no recorded commands yet; record this command after it runs")
        return result
    # NOTE (root-cause fix, issue 2): the single exact-repeat "duplicate
    # command" warning was removed. It fired on *every* re-issue of a command
    # the agent had legitimately just run + synced, forcing a
    # REVIEW -> sync -> REVIEW loop that blocked non-interactive / yolo sessions.
    # Genuine retry loops are still caught by the hard anti-stuck block in
    # sync.py (repeat_count >= RETRY_LIMIT) which BLOCKs after 3+ identical
    # re-issues without progress.
    return result
