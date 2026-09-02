"""Contract tests for the multi-run non-determinism aggregator."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from benchmark import aggregate
from benchmark.aggregate import _classify, aggregate_engagements


def _make_engagement(root: Path, name: str, *, findings: bool, manifest: bool) -> Path:
    path = root / name
    path.mkdir(parents=True, exist_ok=True)
    if findings:
        (path / "evidence").mkdir(parents=True, exist_ok=True)
        (path / "evidence" / "findings.jsonl").write_text("", encoding="utf-8")
    if manifest:
        (path / "run-manifest.json").write_text(json.dumps({"run_id": name}), encoding="utf-8")
    return path


def test_classify_distinguishes_engagement_kinds(tmp_path: Path) -> None:
    complete = _make_engagement(tmp_path, "complete", findings=True, manifest=True)
    incomplete = _make_engagement(tmp_path, "incomplete", findings=False, manifest=True)
    stub = _make_engagement(tmp_path, "stub", findings=False, manifest=False)
    assert _classify(complete) == "complete"
    assert _classify(incomplete) == "incomplete"
    assert _classify(stub) == "stub"


def _fake_score(confirmed_ids: set[str]):
    def _score(eng_dir):
        return {
            "confirmed": len(confirmed_ids),
            "total": 20,
            "finding_score_pct": round(len(confirmed_ids) / 20 * 100, 1),
            "confirmed_details": [{"golden_id": cid} for cid in sorted(confirmed_ids)],
        }

    return _score


def test_aggregate_reports_mean_and_envelope(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    # Three runs confirming {a}, {a,b}, {a,c}: mean 4/3, union {a,b,c}, intersection {a}.
    cases = [{"a"}, {"a", "b"}, {"a", "c"}]
    dirs = []
    for i, _ids in enumerate(cases):
        d = _make_engagement(tmp_path, f"run-{i}", findings=True, manifest=True)
        dirs.append(d)
    # Stub + incomplete dirs must be excluded without affecting the distribution.
    _make_engagement(tmp_path, "tee-stub", findings=False, manifest=False)
    _make_engagement(tmp_path, "still-running", findings=False, manifest=True)

    # Bind each engagement to its own confirmed set deterministically.
    mapping = {str(d.resolve()): ids for d, ids in zip(dirs, cases, strict=True)}

    def _scorer(eng):
        return _fake_score(mapping[str(eng.resolve())])(eng)

    monkeypatch.setattr(aggregate, "score_engagement", _scorer)
    # The aggregator intersects against the full golden universe; scope it to
    # the three synthetic challenge ids so pass^k is computable in this test.
    monkeypatch.setattr(
        aggregate, "load_golden_set", lambda: [{"id": cid} for cid in ("a", "b", "c")]
    )

    result = aggregate_engagements([*dirs, tmp_path / "tee-stub", tmp_path / "still-running"])

    assert result["runs"] == 3
    assert result["total_challenges"] == 3
    assert result["summary"]["mean_confirmed"] == round((1 + 2 + 2) / 3, 3)
    assert result["summary"]["min_confirmed"] == 1
    assert result["summary"]["max_confirmed"] == 2
    assert result["envelope"]["pass_at_k_ids"] == ["a", "b", "c"]
    assert result["envelope"]["pass_caret_k_ids"] == ["a"]
    assert result["incomplete_engagements"] == ["still-running"]
    assert result["skipped_stubs"] == ["tee-stub"]
    assert result["challenge_solve_rate"]["a"] == 1.0
    assert result["challenge_solve_rate"]["b"] == round(1 / 3, 3)


def test_aggregate_excludes_explicitly_incomparable_runs(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    engagement = _make_engagement(tmp_path, "hosted-without-snapshot", findings=True, manifest=True)

    def _scorer(_engagement):
        return {
            **_fake_score({"a"})(_engagement),
            "protocol_alignment": {"comparable": False},
        }

    monkeypatch.setattr(aggregate, "score_engagement", _scorer)
    monkeypatch.setattr(aggregate, "load_golden_set", lambda: [{"id": "a"}])

    result = aggregate_engagements([engagement])

    assert result["runs"] == 0
    assert result["incomparable_engagements"] == ["hosted-without-snapshot"]
