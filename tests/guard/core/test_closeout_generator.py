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
    output = generate_report_md(tmp_path, target="https://example.test")
    text = output.read_text(encoding="utf-8")
    assert "https://example.test" in text
    assert "FIND-001: Arbitrary order read" in text
    assert "| High | 1 |" in text
    assert "evidence/executions/order.json" in text


def test_generators_do_not_overwrite_without_force(tmp_path: Path) -> None:
    _write_finding(tmp_path)
    generate_findings_yaml(tmp_path)
    generate_report_md(tmp_path, target="https://example.test")
    with pytest.raises(ValueError, match="force=True"):
        generate_findings_yaml(tmp_path)
    with pytest.raises(ValueError, match="force=True"):
        generate_report_md(tmp_path, target="https://example.test")
