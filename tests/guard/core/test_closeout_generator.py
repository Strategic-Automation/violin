"""Tests for the closeout artifact generator (FIND parsing + findings.yaml/report.md derivation)."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest
import yaml

from plugins.violin_guard.core.findings import (
    generate_findings_yaml,
    generate_report_md,
    parse_finding_file,
)

FIND_MD = """# FIND-002: IDOR - arbitrary order read

- **Severity:** High
- **Batch:** 356aff5b-1674-4693-8417-96d2e9b55248
- **PTT task:** PT-102
- **Phase:** VULN_RESEARCH
- **Hypothesis:** H-003

## Description

GET /api/v1/orders/{id} performs no ownership check.

## Impact

Horizontal privilege escalation.

## Evidence

- `evidence/executions/2026-08-10T094638-ee4dead5-command.json`
- `evidence/executions/2026-08-10T094638-ee4dead5-command.stdout.txt`

## Remediation

Enforce object-ownership authorization.
"""


# ---------------------------------------------------------------------------
# Task 1: FIND file parser
# ---------------------------------------------------------------------------
def test_parse_finding_file_extracts_fields(tmp_path: Path) -> None:
    f = tmp_path / "FIND-002.md"
    f.write_text(FIND_MD, encoding="utf-8")
    rec = parse_finding_file(f)
    assert rec["id"] == "FIND-002"
    assert rec["title"] == "IDOR - arbitrary order read"
    assert rec["severity"] == "High"
    assert rec["hypothesis"] == "H-003"
    assert rec["phase"] == "VULN_RESEARCH"
    assert rec["ptt_task"] == "PT-102"
    assert rec["batch"] == "356aff5b-1674-4693-8417-96d2e9b55248"
    assert rec["evidence"] == [
        "evidence/executions/2026-08-10T094638-ee4dead5-command.json",
        "evidence/executions/2026-08-10T094638-ee4dead5-command.stdout.txt",
    ]
    assert "no ownership check" in rec["description"]
    assert "object-ownership" in rec["remediation"]


def test_parse_finding_file_rejects_non_finding(tmp_path: Path) -> None:
    f = tmp_path / "notes.md"
    f.write_text("# Not a finding\n", encoding="utf-8")
    with pytest.raises(ValueError):
        parse_finding_file(f)


# ---------------------------------------------------------------------------
# Task 2: findings.yaml generator
# ---------------------------------------------------------------------------
def test_generate_findings_yaml_roundtrip(tmp_path: Path) -> None:
    findings_dir = tmp_path / "evidence" / "findings"
    findings_dir.mkdir(parents=True)
    (findings_dir / "FIND-001.md").write_text(
        FIND_MD.replace("FIND-002", "FIND-001"), encoding="utf-8"
    )
    out = generate_findings_yaml(tmp_path)
    assert out == tmp_path / "evidence" / "reporting" / "findings.yaml"
    data = yaml.safe_load(out.read_text(encoding="utf-8"))
    assert data["findings"][0]["id"] == "FIND-001"
    assert data["findings"][0]["severity"] == "High"
    assert data["findings"][0]["hypothesis"] == "H-003"
    assert len(data["findings"][0]["evidence"]) == 2
    assert "generated_from" in data


def test_generate_findings_yaml_no_findings(tmp_path: Path) -> None:
    with pytest.raises(ValueError):
        generate_findings_yaml(tmp_path)


# ---------------------------------------------------------------------------
# Task 3: report.md generator
# ---------------------------------------------------------------------------
def test_generate_report_md_contents(tmp_path: Path) -> None:
    findings_dir = tmp_path / "evidence" / "findings"
    findings_dir.mkdir(parents=True)
    (findings_dir / "FIND-002.md").write_text(FIND_MD, encoding="utf-8")
    out = generate_report_md(tmp_path, target="https://example.test")
    text = out.read_text(encoding="utf-8")
    assert out == tmp_path / "reporting" / "report.md"
    assert "https://example.test" in text
    assert "FIND-002" in text
    assert "| High | 1 |" in text
    assert "no ownership check" in text
    assert "Executive Summary" in text


def test_generate_report_md_no_overwrite(tmp_path: Path) -> None:
    rep = tmp_path / "reporting" / "report.md"
    rep.parent.mkdir(parents=True)
    rep.write_text("existing", encoding="utf-8")
    with pytest.raises(ValueError):
        generate_report_md(tmp_path, target="https://example.test")


# ---------------------------------------------------------------------------
# Task 4: CLI subcommand
# ---------------------------------------------------------------------------
def test_cli_generate_closeout(tmp_path: Path) -> None:
    findings_dir = tmp_path / "evidence" / "findings"
    findings_dir.mkdir(parents=True)
    (findings_dir / "FIND-001.md").write_text(
        FIND_MD.replace("FIND-002", "FIND-001"), encoding="utf-8"
    )
    repo_root = Path(__file__).resolve().parents[3]
    r = subprocess.run(
        [
            sys.executable,
            "scripts/violin_guard.py",
            "generate-closeout",
            "--eng-dir",
            str(tmp_path),
            "--target",
            "https://example.test",
        ],
        capture_output=True,
        text=True,
        cwd=str(repo_root),
    )
    assert r.returncode == 0, r.stderr
    assert (tmp_path / "evidence" / "reporting" / "findings.yaml").exists()
    assert (tmp_path / "reporting" / "report.md").exists()
