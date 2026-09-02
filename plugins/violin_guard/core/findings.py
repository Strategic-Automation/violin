"""Receipt-backed structured findings and deterministic report rendering."""

from __future__ import annotations

import json
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml

from . import receipt_integrity, schemas, state

FINDINGS_PATH = Path("evidence/findings.jsonl")
_SEVERITY_ORDER = ("Critical", "High", "Medium", "Low", "Info")


def _store_path(engagement: Path) -> Path:
    return engagement / FINDINGS_PATH


def load_findings(eng_dir: str | Path) -> list[dict[str, Any]]:
    """Load the canonical append-only finding records for an engagement."""
    engagement = state.resolve_eng_dir(eng_dir)
    path = _store_path(engagement)
    if not path.is_file():
        return []
    records: list[dict[str, Any]] = []
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        try:
            value = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ValueError(f"{FINDINGS_PATH}:{line_number}: invalid JSON") from exc
        try:
            records.append(schemas.FindingRecordModel.model_validate(value).model_dump())
        except ValueError as exc:
            raise ValueError(f"{FINDINGS_PATH}:{line_number}: invalid finding record") from exc
    return records


def _next_finding_id(records: list[dict[str, Any]]) -> str:
    numbers = [
        int(value.removeprefix("FIND-"))
        for record in records
        if (value := str(record.get("finding_id") or "")).startswith("FIND-")
        and value.removeprefix("FIND-").isdigit()
    ]
    return f"FIND-{max(numbers, default=0) + 1:03d}"


def _verified_receipt(
    engagement: Path, receipt_path: str
) -> tuple[dict[str, Any], tuple[Path, ...]]:
    relative = Path(receipt_path)
    expected_root = (engagement / "evidence" / "executions").resolve()
    candidate = (engagement / relative).resolve()
    if (
        relative.is_absolute()
        or not candidate.is_relative_to(expected_root)
        or candidate.suffix.lower() != ".json"
        or not candidate.is_file()
        or candidate.is_symlink()
    ):
        raise ValueError("receipt_paths must name execution JSON files beneath evidence/executions")
    receipt = state.read_json(candidate)
    verified = receipt_integrity.verify_runtime_receipt(receipt, engagement)
    if verified is None:
        raise ValueError(f"receipt is unsigned, foreign, or has changed evidence: {receipt_path}")
    if receipt.get("status") not in {"completed", "timed_out", "output_limited"}:
        raise ValueError(f"receipt did not execute to a reviewable result: {receipt_path}")
    if receipt.get("exit_code") is None:
        raise ValueError(f"receipt has no exit status: {receipt_path}")
    if not verified:
        raise ValueError(f"receipt contains no authenticated evidence: {receipt_path}")
    return receipt, verified


def _verified_evidence_files(
    engagement: Path,
    evidence_paths: list[str],
    authenticated_paths: set[str],
) -> list[str]:
    """Resolve decisive-evidence files authenticated by the cited receipts."""
    valid: list[str] = []
    evidence_root = (engagement / "evidence").resolve()
    for value in dict.fromkeys(evidence_paths):
        relative = Path(str(value).strip())
        candidate = (engagement / relative).resolve()
        if (
            not str(value).strip()
            or relative.is_absolute()
            or not candidate.is_relative_to(evidence_root)
            or candidate.is_symlink()
            or candidate.suffix.lower() == ".json"
            or not candidate.is_file()
            or candidate.stat().st_size == 0
        ):
            raise ValueError("evidence_paths must name non-empty, non-JSON files beneath evidence/")
        normalized = candidate.relative_to(engagement).as_posix()
        if normalized not in authenticated_paths:
            raise ValueError(
                "evidence_paths must be authenticated by a cited execution receipt; "
                "declare each saved file through violin_exec evidence_outputs"
            )
        valid.append(normalized)
    return valid


_STATUS_LINE_RE = re.compile(rb"HTTP/\d[\x20-\x7e]*", re.I)
_HEADER_LINE_RE = re.compile(rb"[A-Za-z][A-Za-z0-9-]*:[ \t]*\S")
_LABEL_LINE_RE = re.compile(rb"^\s*={2,}.*={2,}\s*$", re.M)


def _head_has_http_bytes(head: bytes) -> bool:
    """True when decisive HTTP response bytes follow the last status line.

    Status-only captures (e.g. a probe closed with ``grep '^HTTP'``) prove the
    request happened but carry no response content: after the last status line
    there are only further status lines, ``=== label ===`` echo markers, and
    whitespace. Real proof shows a header line (``name: value``) or body bytes.
    """
    matches = list(_STATUS_LINE_RE.finditer(head))
    if not matches:
        return False
    tail = head[matches[-1].end() :]
    if _HEADER_LINE_RE.search(tail):
        return True
    cleaned = _LABEL_LINE_RE.sub(b"", tail)
    cleaned = _STATUS_LINE_RE.sub(b"", cleaned)
    return bool(re.sub(rb"[\s\x00-\x1f]+", b"", cleaned))


def _proof_byte_warnings(
    engagement: Path,
    verified_paths: list[str],
    saved_evidence: list[str],
) -> list[str]:
    """Warn (never block) when a finding's proof chain lacks HTTP response bytes.

    A receipt whose stdout shows only status lines proves the request happened
    but carries no response content. Attaching the saved probe file via
    ``evidence_paths`` restores the decisive bytes to the proof chain.
    """
    for relative in [*verified_paths, *saved_evidence]:
        path = engagement / relative
        try:
            with path.open("rb") as handle:
                head = handle.read(4096)
        except OSError:
            continue
        if _head_has_http_bytes(head):
            return []
    return [
        "finding proof carries no literal HTTP response bytes; attach the decisive "
        "evidence file(s) via evidence_paths or echo a body excerpt in the probe "
        "command so receipts capture it"
    ]


def submit_finding(
    eng_dir: str | Path,
    *,
    title: str,
    severity: str,
    summary: str,
    receipt_paths: list[str],
    evidence_paths: list[str] | None = None,
) -> dict[str, Any]:
    """Persist one generic finding without exposing evaluator challenge metadata."""
    engagement = state.resolve_eng_dir(eng_dir)
    normalized_receipts = list(
        dict.fromkeys(value.strip() for value in receipt_paths if value.strip())
    )
    verified_paths: list[str] = []
    execution_ids: list[str] = []
    for receipt_path in normalized_receipts:
        receipt, verified = _verified_receipt(engagement, receipt_path)
        execution_ids.append(str(receipt.get("execution_id") or ""))
        verified_paths.extend(path.relative_to(engagement).as_posix() for path in verified)

    evidence_paths = evidence_paths or []
    saved_evidence = _verified_evidence_files(
        engagement,
        evidence_paths,
        set(verified_paths),
    )

    warnings = _proof_byte_warnings(engagement, verified_paths, saved_evidence)

    store = _store_path(engagement)
    with state.workflow_lock(engagement), state.lock_file(store.with_suffix(".lock")):
        records = load_findings(engagement)
        signature = {
            "title": title.strip().casefold(),
            "receipt_paths": normalized_receipts,
        }
        existing = next(
            (
                record
                for record in records
                if {
                    "title": str(record.get("title") or "").strip().casefold(),
                    "receipt_paths": record.get("receipt_paths"),
                }
                == signature
            ),
            None,
        )
        if existing:
            return {
                **existing,
                "duplicate": True,
                "receipt_validation": "verified",
                "warnings": _proof_byte_warnings(
                    engagement, [], existing.get("evidence_paths") or []
                ),
            }

        record = {
            "schema_version": 1,
            "finding_id": _next_finding_id(records),
            "title": title.strip(),
            "severity": severity,
            "summary": summary.strip(),
            "status": "validated",
            "receipt_paths": normalized_receipts,
            "evidence_paths": saved_evidence,
            "execution_ids": execution_ids,
            "created_at": datetime.now(UTC).isoformat(),
            "engagement_id": engagement.name,
        }
        state.ensure_dir(store.parent)
        with store.open("a", encoding="utf-8", newline="\n") as handle:
            handle.write(json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n")
        return {
            **record,
            "duplicate": False,
            "receipt_validation": "verified",
            "warnings": warnings,
        }


def _validated_records(engagement: Path) -> list[dict[str, Any]]:
    return load_findings(engagement)


def generate_findings_yaml(eng_dir: str | Path, *, force: bool = False) -> Path:
    """Render a machine-readable finding summary from the canonical JSONL store."""
    engagement = state.resolve_eng_dir(eng_dir)
    records = _validated_records(engagement)
    if not records:
        raise ValueError("no validated findings in evidence/findings.jsonl")
    output = engagement / "evidence" / "reporting" / "findings.yaml"
    if output.exists() and not force:
        raise ValueError("findings.yaml exists; pass force=True to regenerate")
    state.ensure_dir(output.parent)
    output.write_text(
        yaml.safe_dump(
            {"engagement": engagement.name, "findings": records},
            sort_keys=False,
            allow_unicode=True,
        ),
        encoding="utf-8",
    )
    return output


def generate_report_md(eng_dir: str | Path, *, target: str, force: bool = False) -> Path:
    """Render the human report from canonical structured finding records."""
    engagement = state.resolve_eng_dir(eng_dir)
    records = _validated_records(engagement)
    if not records:
        raise ValueError("no validated findings in evidence/findings.jsonl")
    output = engagement / "reporting" / "report.md"
    if output.exists() and not force:
        raise ValueError("report.md exists; pass force=True to regenerate")
    counts = {
        severity: sum(1 for record in records if record["severity"] == severity)
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
        "<!-- Narrative placeholder: describe engagement posture, threat context, "
        "and overall risk in free-form prose here. -->",
        "",
        "",
        "## Severity Summary",
        "",
        "| Severity | Count |",
        "|----------|-------|",
        *[f"| {severity} | {counts[severity]} |" for severity in _SEVERITY_ORDER],
        "",
    ]
    for record in records:
        lines.extend(
            [
                f"## {record['finding_id']}: {record['title']}",
                "",
                f"- **Severity:** {record['severity']}",
                "",
                record["summary"],
                "",
                "### Evidence",
                "",
                *[f"- `{path}`" for path in record["receipt_paths"]],
                "",
            ]
        )
    state.ensure_dir(output.parent)
    output.write_text("\n".join(lines).rstrip() + "\n", encoding="utf-8")
    return output


__all__ = [
    "FINDINGS_PATH",
    "generate_findings_yaml",
    "generate_report_md",
    "load_findings",
    "submit_finding",
]
