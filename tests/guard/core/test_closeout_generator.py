"""Tests for reports rendered from the structured finding store."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml

from plugins.violin_guard.core.findings import generate_findings_yaml, generate_report_md


def _write_finding(engagement: Path) -> None:
    path = engagement / "evidence" / "findings.jsonl"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "finding_id": "FIND-001",
                "title": "Arbitrary order read",
                "severity": "High",
                "summary": "A user can read an order owned by another account.",
                "status": "validated",
                "receipt_paths": ["evidence/executions/order.json"],
                "execution_ids": ["exec-1"],
                "evidence_paths": ["evidence/executions/order.stdout.txt"],
            }
        )
        + "\n",
        encoding="utf-8",
    )


def test_generate_findings_yaml_roundtrip(tmp_path: Path) -> None:
    _write_finding(tmp_path)
    output = generate_findings_yaml(tmp_path)
    data = yaml.safe_load(output.read_text(encoding="utf-8"))
    assert output == tmp_path / "evidence" / "reporting" / "findings.yaml"
    assert data["findings"][0]["finding_id"] == "FIND-001"
    assert data["findings"][0]["receipt_paths"] == ["evidence/executions/order.json"]


def test_generate_closeout_requires_validated_findings(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="no validated findings"):
        generate_findings_yaml(tmp_path)
    with pytest.raises(ValueError, match="no validated findings"):
        generate_report_md(tmp_path, target="https://example.test")


def test_generate_report_md_contents(tmp_path: Path) -> None:
    _write_finding(tmp_path)
    target = "https://example.test"
    output = generate_report_md(tmp_path, target=target)
    text = output.read_text(encoding="utf-8")
    assert f"- **Target:** {target}" in text
    assert "FIND-001: Arbitrary order read" in text
    assert "| High | 1 |" in text
    assert "evidence/executions/order.json" in text


def test_report_renders_both_receipts_and_declared_evidence_distinctly(
    tmp_path: Path,
) -> None:
    _write_finding(tmp_path)
    text = generate_report_md(tmp_path, target="https://example.test").read_text(encoding="utf-8")
    assert "**Authenticating receipts (signed execution receipts):**" in text
    assert "- `evidence/executions/order.json`" in text
    assert "**Declared evidence (decisive response bytes):**" in text
    assert "- `evidence/executions/order.stdout.txt`" in text
    # The two sets differ, so the report states the difference rather than
    # collapsing the declared evidence into the receipts.
    assert "distinct sets" in text


def test_report_marks_finding_with_no_declared_evidence(tmp_path: Path) -> None:
    engagement = Path(tmp_path)
    store = engagement / "evidence" / "findings.jsonl"
    store.parent.mkdir(parents=True, exist_ok=True)
    record = {
        "schema_version": 1,
        "finding_id": "FIND-002",
        "title": "Status-code only probe",
        "severity": "Low",
        "summary": "Flagged by a status-code-only probe with no saved response body.",
        "status": "validated",
        "receipt_paths": ["evidence/executions/probe.json"],
        "execution_ids": ["exec-2"],
        "evidence_paths": [],
    }
    store.write_text(
        json.dumps(record) + "\n",
        encoding="utf-8",
    )
    text = generate_report_md(engagement, target="https://example.test").read_text(encoding="utf-8")
    assert "evidence_complete: false" in text
    assert "no declared evidence_paths" in text


def test_generators_do_not_overwrite_without_force(tmp_path: Path) -> None:
    _write_finding(tmp_path)
    generate_findings_yaml(tmp_path)
    generate_report_md(tmp_path, target="https://example.test")
    with pytest.raises(ValueError, match="force=True"):
        generate_findings_yaml(tmp_path)
    with pytest.raises(ValueError, match="force=True"):
        generate_report_md(tmp_path, target="https://example.test")


@pytest.mark.parametrize(
    "entry_point",
    [
        ["scripts/violin_guard.py", "generate-closeout"],
        ["scripts/generate-closeout.py"],
        ["scripts/generate-closeout.py", "generate-closeout"],
    ],
)
def test_closeout_cli_success_refusal_and_force(tmp_path, entry_point):
    import subprocess
    import sys

    root = Path(__file__).resolve().parents[3]
    engagement = tmp_path / "engagement with spaces"
    _write_finding(engagement)
    invocation = [
        sys.executable,
        str(root / entry_point[0]),
        *entry_point[1:],
        "--eng-dir",
        str(engagement),
        "--target",
        "https://example.test",
    ]

    def run(*extra):
        return subprocess.run(
            [*invocation, *extra],
            cwd=tmp_path,
            capture_output=True,
            text=True,
            check=False,
            timeout=15,
        )

    yaml_path = engagement / "evidence" / "reporting" / "findings.yaml"
    report_path = engagement / "reporting" / "report.md"
    result = run()
    expected = f"OK: wrote {yaml_path}\nOK: wrote {report_path}\n"
    assert result.returncode == 0, result.stderr
    assert result.stdout == expected
    assert result.stderr == ""
    original = (yaml_path.read_bytes(), report_path.read_bytes())
    result = run()
    assert result.returncode == 1
    assert result.stdout.startswith("BLOCK: ")
    assert "force=True" in result.stdout
    assert "OK:" not in result.stdout
    assert (yaml_path.read_bytes(), report_path.read_bytes()) == original
    result = run("--force")
    assert result.returncode == 0, result.stderr
    assert result.stdout == expected
    assert (yaml_path.read_bytes(), report_path.read_bytes()) == original
    (engagement / "evidence" / "findings.jsonl").unlink()
    result = run("--force")
    assert result.returncode == 1
    assert result.stdout == "BLOCK: no validated findings in evidence/findings.jsonl\n"
