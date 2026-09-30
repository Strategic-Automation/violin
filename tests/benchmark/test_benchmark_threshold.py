from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from benchmark.score import score_engagement


@pytest.mark.parametrize("finding_count, expected_pass", [(16, False), (17, True)])
def test_confirmed_findings_enforce_eighty_five_percent_threshold(
    tmp_path: Path, finding_count: int, expected_pass: bool
) -> None:
    fixture = Path("benchmark/targets/duck-store/calibration/known-good")
    engagement = tmp_path / "known-good"
    shutil.copytree(fixture, engagement)
    findings_path = engagement / "evidence" / "findings.jsonl"
    finding_lines = findings_path.read_text(encoding="utf-8").splitlines()
    findings_path.write_text("\n".join(finding_lines[:finding_count]) + "\n", encoding="utf-8")

    result = score_engagement(engagement, trusted_fixture=True)

    assert result["confirmed"] == finding_count
    assert result["total"] == 20
    assert result["finding_score_pct"] == finding_count * 5.0
    assert result["benchmark_pass"] is expected_pass
