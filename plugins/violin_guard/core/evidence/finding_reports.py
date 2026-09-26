"""Render structured findings into closeout report artifacts."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from ...core.engagement import state

_SEVERITY_ORDER = ("Critical", "High", "Medium", "Low", "Info")


def generate_findings_yaml(
    engagement: Path, records: list[dict[str, Any]], *, force: bool = False
) -> Path:
    """Render a machine-readable finding summary from validated records."""
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


def _evidence_lines(record: dict[str, Any]) -> list[str]:
    """Render the per-finding Evidence section with both proof roles labelled.

    Receipts authenticate that the cited command executed and name the files it
    wrote; the declared ``evidence_paths`` carry the decisive response bytes the
    finding rests on. Both sets are rendered, the difference between them is
    stated when they are not identical (rather than dropping either), and a
    finding with no declared evidence is visibly marked under the
    ``evidence_complete`` semantics of #124.
    """
    receipts = list(record.get("receipt_paths") or [])
    evidence = list(record.get("evidence_paths") or [])
    lines = [
        "### Evidence",
        "",
        "**Authenticating receipts (signed execution receipts):**",
        "",
        *[f"- `{path}`" for path in receipts],
        "",
        "**Declared evidence (decisive response bytes):**",
        "",
    ]
    if evidence:
        lines.extend(f"- `{path}`" for path in evidence)
    else:
        lines.append(
            "> Note: no declared evidence_paths — evidence_complete: false "
            "(proof carries no literal HTTP response bytes)."
        )
    lines.append("")
    if set(evidence) != set(receipts):
        lines.extend(
            [
                "> The declared evidence and the authenticating receipts are distinct "
                + "sets: the receipts prove the command executed, while the declared "
                + "evidence holds the decisive response bytes.",
                "",
            ]
        )
    return lines


def generate_report_md(
    engagement: Path, records: list[dict[str, Any]], *, target: str, force: bool = False
) -> Path:
    """Render the human report from validated structured finding records."""
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
        "<!-- Describe engagement posture, threat context, and overall risk here. -->",
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
                *_evidence_lines(record),
            ]
        )
    state.ensure_dir(output.parent)
    output.write_text("\n".join(lines).rstrip() + "\n", encoding="utf-8")
    return output
