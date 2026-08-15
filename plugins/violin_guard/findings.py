"""Structured finding creation from guarded execution receipts."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import yaml

from . import hypotheses, state

_FINDING_ID_RE = re.compile(r"FIND-(\d{3,})$")
_SEVERITIES = {"critical", "high", "medium", "low", "info"}


def _next_finding_id(directory: Path) -> str:
    numbers = []
    for path in directory.glob("FIND-*.md"):
        match = _FINDING_ID_RE.fullmatch(path.stem)
        if match:
            numbers.append(int(match.group(1)))
    return f"FIND-{max(numbers, default=0) + 1:03d}"


def _batch_evidence(eng_dir: Path, pending: dict[str, Any]) -> list[str]:
    unmatched = {str(item.get("command") or "") for item in pending.get("commands") or []}
    evidence: list[str] = []
    manifests = sorted(
        (eng_dir / "evidence" / "executions").glob("*.json"),
        key=lambda path: path.stat().st_mtime_ns,
        reverse=True,
    )
    for manifest in manifests:
        receipt = state.read_json(manifest)
        command = str(receipt.get("command") or "")
        if command not in unmatched:
            continue
        unmatched.remove(command)
        for value in (receipt.get("evidence_paths") or {}).values():
            relative = str(value or "").strip()
            if relative and (eng_dir / relative).is_file() and relative not in evidence:
                evidence.append(relative)
    return evidence


def _existing_batch_finding(directory: Path, batch_id: str) -> Path | None:
    marker = f"- **Batch:** {batch_id}"
    for path in sorted(directory.glob("FIND-*.md")):
        try:
            if marker in path.read_text(encoding="utf-8").splitlines():
                return path
        except OSError:
            continue
    return None


def _validate_from_pending_batch(
    eng_dir: str | Path,
    pending: dict[str, Any],
    *,
    title: str,
    severity: str,
    description: str,
    impact: str,
    remediation: str,
    finding_id: str = "",
    hypothesis_id: str = "",
) -> dict[str, Any]:
    engagement = state.resolve_eng_dir(eng_dir)
    values = {
        "title": title.strip(),
        "description": description.strip(),
        "impact": impact.strip(),
        "remediation": remediation.strip(),
    }
    severity_key = severity.strip().lower()
    if not all(values.values()):
        raise ValueError("title, description, impact, and remediation must be non-empty")
    if severity_key not in _SEVERITIES:
        raise ValueError("severity must be one of Critical, High, Medium, Low, or Info")
    identifier = finding_id.strip().upper()
    if identifier and not _FINDING_ID_RE.fullmatch(identifier):
        raise ValueError("finding_id must use FIND-NNN format")
    if not identifier:
        identifier = _next_finding_id(engagement / "evidence" / "findings")
    evidence = _batch_evidence(engagement, pending)
    if not evidence:
        raise ValueError("the current batch has no completed execution receipts to cite")
    normalized_hypothesis = hypothesis_id.strip().upper().removeprefix("H-").zfill(3)
    hypothesis = next(
        (
            item
            for item in hypotheses.parse_hypotheses(engagement / "hypotheses.md")
            if item.id == normalized_hypothesis
        ),
        None,
    )
    if (
        not hypothesis
        or hypothesis.canonical_status() != "Validated"
        or not hypothesis.runtime_evidence
    ):
        raise ValueError("a finding requires a linked Validated hypothesis with runtime_evidence")
    return {
        **values,
        "severity": severity_key,
        "finding_id": identifier,
        "evidence_paths": evidence,
        "hypothesis_id": f"H-{hypothesis.id}",
    }


def _create_from_pending_batch(
    eng_dir: str | Path,
    *,
    title: str,
    severity: str,
    description: str,
    impact: str,
    remediation: str,
    finding_id: str = "",
    hypothesis_id: str = "",
    pending: dict[str, Any] | None = None,
) -> dict[str, Any]:
    engagement = state.resolve_eng_dir(eng_dir)
    pending = pending or state.get_pending_sync(engagement)
    if not pending:
        raise ValueError("no current execution batch; run guarded validation commands first")
    draft = _validate_from_pending_batch(
        engagement,
        pending,
        title=title,
        severity=severity,
        description=description,
        impact=impact,
        remediation=remediation,
        finding_id=finding_id,
        hypothesis_id=hypothesis_id,
    )

    directory = engagement / "evidence" / "findings"
    state.ensure_dir(directory)
    batch_id = str(pending.get("batch_id") or "")
    existing = _existing_batch_finding(directory, batch_id)
    if existing:
        if draft["finding_id"] and draft["finding_id"] != existing.stem:
            raise ValueError(
                f"batch {batch_id} already has finding {existing.stem}; "
                f"refusing requested {draft['finding_id']}"
            )
        return {
            "finding_id": existing.stem,
            "path": existing.relative_to(engagement).as_posix(),
            "evidence_paths": draft["evidence_paths"],
            "batch_id": batch_id,
            "reused": True,
        }

    identifier = draft["finding_id"] or _next_finding_id(directory)
    output = directory / f"{identifier}.md"
    if output.exists():
        raise ValueError(f"finding already exists: {output}")

    commands = [str(item.get("command") or "") for item in pending.get("commands") or []]
    lines = [
        f"# {identifier}: {draft['title']}",
        "",
        f"- **Severity:** {draft['severity'].title()}",
        f"- **Batch:** {batch_id or 'unknown'}",
        f"- **PTT task:** {pending.get('ptt_task_id') or 'unknown'}",
        f"- **Phase:** {pending.get('phase') or 'unknown'}",
        f"- **Hypothesis:** {draft['hypothesis_id']}",
        "",
        "## Description",
        "",
        draft["description"],
        "",
        "## Impact",
        "",
        draft["impact"],
        "",
        "## Evidence",
        "",
        *[f"- `{path}`" for path in draft["evidence_paths"]],
        "",
        "## Reproduction commands",
        "",
        "```text",
        *commands,
        "```",
        "",
        "## Remediation",
        "",
        draft["remediation"],
        "",
    ]
    temporary = output.with_suffix(output.suffix + ".tmp")
    temporary.write_text("\n".join(lines), encoding="utf-8")
    temporary.replace(output)
    return {
        "finding_id": identifier,
        "path": output.relative_to(engagement).as_posix(),
        "evidence_paths": draft["evidence_paths"],
        "batch_id": batch_id,
        "reused": False,
    }


# ---------------------------------------------------------------------------
# Closeout artifact generation (FIND parsing + derived exports)
# ---------------------------------------------------------------------------
_HEADING_RE = re.compile(r"^# (FIND-\d{3,}):\s*(?P<title>.+)$")
_BULLET_RE = re.compile(r"^- \*\*(?P<key>[^:*]+):\*\*\s*(?P<value>.*)$")
_SECTION_RE = re.compile(r"^## (?P<name>.+)$")
_EVIDENCE_ITEM_RE = re.compile(r"^- `(?P<path>[^`]+)`\s*$")

_FIELD_KEYS = {
    "severity": "severity",
    "hypothesis": "hypothesis",
    "phase": "phase",
    "ptt task": "ptt_task",
    "batch": "batch",
}

_SECTION_FIELDS = {
    "Description": "description",
    "Impact": "impact",
    "Remediation": "remediation",
}

_SEVERITY_ORDER = ("Critical", "High", "Medium", "Low", "Info")


def parse_finding_file(path: Path) -> dict[str, Any]:
    """Parse a canonical FIND-NNN.md into a flat record dict."""
    text = path.read_text(encoding="utf-8")
    lines = text.splitlines()
    heading = _HEADING_RE.match(lines[0].strip()) if lines else None
    if not heading:
        raise ValueError(f"{path.name}: first line must be '# FIND-NNN: <title>'")
    record: dict[str, Any] = {
        "id": heading.group(1),
        "title": heading.group("title").strip(),
        "severity": "",
        "hypothesis": "",
        "phase": "",
        "ptt_task": "",
        "batch": "",
        "description": "",
        "impact": "",
        "evidence": [],
        "remediation": "",
    }
    section = ""
    section_buf: list[str] = []

    def flush() -> None:
        key = _SECTION_FIELDS.get(section)
        if key:
            record[key] = "\n".join(section_buf).strip()

    for raw in lines[1:]:
        line = raw.strip()
        sec = _SECTION_RE.match(line)
        if sec:
            flush()
            section = sec.group("name").strip()
            section_buf = []
            continue
        bullet = _BULLET_RE.match(line)
        if bullet and not section:
            key = _FIELD_KEYS.get(bullet.group("key").strip().lower())
            if key:
                record[key] = bullet.group("value").strip()
            continue
        if section == "Evidence":
            item = _EVIDENCE_ITEM_RE.match(line)
            if item:
                record["evidence"].append(item.group("path").strip())
        else:
            section_buf.append(raw)
    flush()
    return record


def generate_findings_yaml(eng_dir: str | Path, *, force: bool = False) -> Path:
    """Write evidence/reporting/findings.yaml derived from FIND-*.md files."""
    engagement = Path(eng_dir)
    findings = sorted((engagement / "evidence" / "findings").glob("FIND-*.md"))
    if not findings:
        raise ValueError("no FIND-*.md files under evidence/findings/")
    out = engagement / "evidence" / "reporting" / "findings.yaml"
    if out.exists() and not force:
        raise ValueError("findings.yaml exists; pass force=True to regenerate")
    records = [parse_finding_file(path) for path in findings]
    payload = {
        "engagement": engagement.name,
        "generated_from": ", ".join(path.name for path in findings),
        "note": (
            "Derived export generated by violin_guard generate-closeout. "
            "The canonical records are the per-finding Markdown files; "
            "this YAML is a machine-readable summary."
        ),
        "findings": [
            {
                "id": rec["id"],
                "title": rec["title"],
                "severity": rec["severity"],
                "hypothesis": rec["hypothesis"],
                "phase": rec["phase"],
                "evidence": rec["evidence"],
            }
            for rec in records
        ],
    }
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(yaml.safe_dump(payload, sort_keys=False, allow_unicode=True), encoding="utf-8")
    return out


def generate_report_md(eng_dir: str | Path, *, target: str, force: bool = False) -> Path:
    """Write reporting/report.md assembled from FIND-*.md records."""
    engagement = Path(eng_dir)
    out = engagement / "reporting" / "report.md"
    if out.exists() and not force:
        raise ValueError("report.md exists; pass force=True to regenerate")
    findings = sorted((engagement / "evidence" / "findings").glob("FIND-*.md"))
    if not findings:
        raise ValueError("no FIND-*.md files under evidence/findings/")
    records = [parse_finding_file(path) for path in findings]
    counts = {
        severity: sum(1 for rec in records if rec["severity"].lower() == severity.lower())
        for severity in _SEVERITY_ORDER
    }
    lines = [
        f"# Security Assessment Report — {target}",
        "",
        f"- **Engagement:** {engagement.name}",
        f"- **Target:** {target}",
        f"- **Findings:** {len(records)}",
        "",
        "## Executive Summary",
        "",
        "<!-- Write 3-6 sentences: overall posture, worst findings, key themes. -->",
        "",
        "| Severity | Count |",
        "|----------|-------|",
    ]
    for severity in _SEVERITY_ORDER:
        lines.append(f"| {severity} | {counts[severity]} |")
    lines.append("")
    for rec in records:
        lines += [
            f"## {rec['id']}: {rec['title']}",
            "",
            f"- **Severity:** {rec['severity']}",
        ]
        if rec["hypothesis"]:
            lines.append(f"- **Hypothesis:** {rec['hypothesis']}")
        if rec["phase"]:
            lines.append(f"- **Phase:** {rec['phase']}")
        lines += [
            "",
            "### Description",
            "",
            rec["description"],
            "",
            "### Impact",
            "",
            rec["impact"],
            "",
            "### Evidence",
            "",
            *[f"- `{item}`" for item in rec["evidence"]],
            "",
            "### Remediation",
            "",
            rec["remediation"],
            "",
        ]
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text("\n".join(lines).rstrip() + "\n", encoding="utf-8")
    return out
