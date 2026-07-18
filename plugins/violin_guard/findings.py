"""Structured finding creation from guarded execution receipts."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from . import state

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
    evidence = _batch_evidence(engagement, pending)
    if not evidence:
        raise ValueError("the current batch has no completed execution receipts to cite")
    return {
        **values,
        "severity": severity_key,
        "finding_id": identifier,
        "evidence_paths": evidence,
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
    )

    directory = engagement / "evidence" / "findings"
    directory.mkdir(parents=True, exist_ok=True)
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
