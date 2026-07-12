"""Freshness / drift guards for engagement artifacts.

Closes artifact-discipline gaps in the engagement guards:

All freshness signals are WARNING-level (exit 2) so they surface drift without
hard-blocking a legitimate command; the skill-load *presence* gate is the only
ERROR (exit 1) because running target commands without the skill loaded is the
Nimbus-class failure the guard exists to prevent.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from pathlib import Path

from guard.core import CheckResult

# Engagement artifacts older than this are flagged as stale (warning, not block).
MAX_PTT_AGE_HOURS = 24
MAX_HYPOTHESIS_AGE_HOURS = 24
MAX_SKILL_MARKER_AGE_HOURS = 24

_DONE_MARKERS = {"[x]", "[~]", "[!]", "[-]"}
_TS_PATTERN = r"(\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2})"


def _parse_ts(value: str) -> datetime | None:
    value = value.strip().replace("T", " ")
    for fmt in ("%Y-%m-%d %H:%M", "%Y-%m-%d %H:%M:%S"):
        try:
            return datetime.strptime(value, fmt)
        except ValueError:
            continue
    return None


def _age_hours(ts: datetime) -> float:
    return (datetime.now() - ts).total_seconds() / 3600.0


def check_skill_load_gate(
    skill_loaded_file: str,
    mandatory: bool,
    max_age_hours: int = MAX_SKILL_MARKER_AGE_HOURS,
) -> CheckResult:
    result = CheckResult()
    marker = Path(skill_loaded_file) if skill_loaded_file else None
    if not marker or not marker.exists() or not marker.is_file():
        if mandatory:
            result.add_error("skill load gate: SKILL.md not marked loaded for this session — load it before any target command")
            result.add_info("load with: read_file path=skills/pentest/SKILL.md")
            result.add_info("then run: python scripts/violin_guard.py check-skill-loaded --eng-dir \"$ENG_DIR\" --session-id \"<session label>\"")
        else:
            result.add_warning("skill load gate: no --skill-loaded-file/--session-id passed; SKILL.md load not verified")
        return result
    ts = _parse_ts_from_mtime(marker)
    if ts is not None and _age_hours(ts) > max_age_hours:
        result.add_warning(
            f"skill load marker is {_age_hours(ts):.0f}h old (>{max_age_hours}h); "
            f"reload skills/pentest/SKILL.md after context compression / resume"
        )
    return result


def _parse_ts_from_mtime(path: Path) -> datetime | None:
    try:
        return datetime.fromtimestamp(path.stat().st_mtime)
    except OSError:
        return None


def check_ptt_freshness(
    ptt_path: Path,
    phase: str,
    max_age_hours: int = MAX_PTT_AGE_HOURS,
) -> CheckResult:
    result = CheckResult()
    if not ptt_path.exists() or not ptt_path.is_file():
        result.add_error(f"PTT missing: {ptt_path}")
        result.add_info("bootstrap with: cp skills/pentest/templates/ptt.md \"$ENG_DIR/state/ptt.md\"")
        return result

    text = ptt_path.read_text(encoding="utf-8", errors="replace")
    lines = text.splitlines()

    # 1) "Last updated" freshness
    last_updated = None
    for line in lines:
        if "last updated" in line.lower():
            m = __import__("re").search(_TS_PATTERN, line)
            if m:
                last_updated = _parse_ts(m.group(1))
                break
    if last_updated is None:
        result.add_warning("PTT has no 'Last updated' timestamp — set it after every tool batch")
    elif _age_hours(last_updated) > max_age_hours:
        result.add_warning(
            f"PTT last updated {_age_hours(last_updated):.0f}h ago (>{max_age_hours}h); "
            f"update it after every batch (rule: never start a new batch without reading this file)"
        )

    # 2) Desync: earlier phases all [ ] while later phases have recorded progress.
    any_done = any(f" {marker} " in text for marker in ("[x]", "[~]", "[!]", "[-]"))
    if any_done and phase in {"EXPLOITATION", "REPORTING", "RETROSPECTIVE"}:
        import re
        phase_sections: list[tuple[str, list[str]]] = []
        current = None
        rows: list[str] = []
        for line in lines:
            pm = re.match(r"^##\s+Phase:\s*(\w+)", line)
            if pm:
                if current is not None:
                    phase_sections.append((current, rows))
                current = pm.group(1).upper()
                rows = []
            elif current is not None and line.strip().startswith("|") and "PT-" in line:
                rows.append(line)
        if current is not None:
            phase_sections.append((current, rows))
        order = ["SCOPING", "RECON", "VULN_RESEARCH", "EXPLOITATION", "REPORTING", "RETROSPECTIVE"]
        reached = {p for p, _ in phase_sections if p in order}
        for p, prows in phase_sections:
            if p in order and p != "RETROSPECTIVE" and prows:
                has_progress = any(any(f" {m} " in r for m in _DONE_MARKERS) for r in prows)
                if not has_progress and order.index(p) < order.index(phase) and p in reached:
                    result.add_warning(
                        f"PTT phase {p} shows all [ ] but later-phase work is recorded as done — "
                        f"mark {p} rows to reflect actual progress"
                    )
    return result


def check_hypotheses_freshness(
    hyp_path: Path,
    phase: str,
    max_age_hours: int = MAX_HYPOTHESIS_AGE_HOURS,
) -> CheckResult:
    result = CheckResult()
    if not hyp_path.exists() or not hyp_path.is_file():
        result.add_error(f"hypotheses.md missing: {hyp_path}")
        result.add_info("bootstrap with: cp skills/pentest/templates/hypothesis-board.md \"$ENG_DIR/hypotheses.md\"")
        return result

    import re
    text = hyp_path.read_text(encoding="utf-8", errors="replace")
    # Split into H-XXX blocks (Active Theories + Resolved Theories)
    blocks = re.split(r"^###\s+(H-\d+):", text, flags=re.MULTILINE)
    # blocks: [pre, id1, body1, id2, body2, ...]
    entries: list[tuple[str, str]] = []
    for i in range(1, len(blocks), 2):
        entries.append((blocks[i], blocks[i + 1] if i + 1 < len(blocks) else ""))

    def field(body: str, name: str) -> str:
        m = re.search(rf"\*\*{name}:\*\*\s*(.+)", body)
        return m.group(1).strip() if m else ""

    stale_entries = 0
    contradiction = False
    for hid, body in entries:
        status = field(body, "Status")
        updated = field(body, "Updated")
        ts = _parse_ts(updated) if updated else None
        if status in {"Validated", "Rejected"}:
            if ts is None:
                result.add_warning(f"hypothesis {hid} is {status} but has no 'Updated' timestamp")
                stale_entries += 1
            elif _age_hours(ts) > max_age_hours:
                result.add_warning(f"hypothesis {hid} ({status}) last updated {_age_hours(ts):.0f}h ago (>{max_age_hours}h)")
                stale_entries += 1
        if status == "Candidate":
            linked = field(body, "Linked findings")
            if linked and linked.upper().startswith("FIND-"):
                result.add_warning(f"hypothesis {hid} is Candidate but already links {linked} — promote to Validated/Rejected")
                contradiction = True

    if phase in {"REPORTING", "RETROSPECTIVE"}:
        resolved = re.search(r"##\s+Resolved Theories", text)
        if resolved:
            tail = text[resolved.start():]
            if not re.search(r"H-\d+:", tail):
                result.add_warning("hypotheses.md 'Resolved Theories' is empty at reporting time — record validated/rejected theories")
    return result


def check_findings_freshness(eng_dir: Path, phase: str) -> CheckResult:
    result = CheckResult()
    if phase not in {"VULN_RESEARCH", "EXPLOITATION", "REPORTING", "RETROSPECTIVE"}:
        return result
    candidates = [
        eng_dir / "evidence" / "vuln-research" / "findings.md",
        eng_dir / "evidence" / "findings.md",
        eng_dir / "state" / "findings.md",
    ]
    found = [p for p in candidates if p.exists() and p.is_file()]
    if not found:
        result.add_warning("no findings file found (e.g. evidence/vuln-research/findings.md) — record findings as they emerge")
        return result
    if all(p.read_text(encoding="utf-8", errors="replace").strip() == "" for p in found):
        result.add_warning("findings file exists but is empty — populate it as findings are validated")
    return result
