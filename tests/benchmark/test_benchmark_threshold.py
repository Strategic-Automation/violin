from __future__ import annotations

import shutil
from pathlib import Path

from benchmark.score import score_engagement


def test_fifteen_of_twenty_confirmed_findings_meets_score_threshold(tmp_path: Path) -> None:
    fixture = Path("benchmark/targets/duck-store/calibration/known-good")
    engagement = tmp_path / "known-good"
    shutil.copytree(fixture, engagement)
    findings_path = engagement / "evidence" / "findings.jsonl"
    finding_lines = findings_path.read_text(encoding="utf-8").splitlines()
    findings_path.write_text("\n".join(finding_lines[:15]) + "\n", encoding="utf-8")

    result = score_engagement(engagement, trusted_fixture=True)

    assert result["confirmed"] == 15
    assert result["total"] == 20
    assert result["finding_score_pct"] == 75.0
    assert result["benchmark_pass"] is True
