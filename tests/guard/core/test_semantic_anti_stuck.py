"""Deterministic semantic no-progress counters and unlock requirements."""

from __future__ import annotations

import json

from plugins.violin_guard.core.engagement import state


def _review(eng, **changes):
    values = {
        "task_id": "PT-010",
        "hypothesis_id": "H-001",
        "skill": "pentest",
        "technique": "directory-enumeration",
        "outcome": "no_progress",
        "evidence_paths": [],
        "next_action": "research a different approach",
        "next_technique": "directory-enumeration",
    }
    values.update(changes)
    return state.record_semantic_review(eng, **values)


def test_semantic_reviews_warn_then_hard_lock_and_require_research_pivot(tmp_path) -> None:
    for _ in range(2):
        assert not _review(tmp_path)["warning"]
    assert _review(tmp_path)["warning"]
    assert _review(tmp_path)["warning"]
    locked = _review(tmp_path)
    assert locked["locked"]
    assert state.semantic_lock(tmp_path)

    assert _review(tmp_path, next_technique="parameter-discovery")["locked"]
    state.record_research_attempt(tmp_path, "web_search", True)
    unlocked = _review(tmp_path, next_technique="parameter-discovery")
    assert not unlocked["locked"]
    assert state.semantic_lock(tmp_path) is None


def test_evidence_backed_progress_resets_the_semantic_counter(tmp_path) -> None:
    _review(tmp_path)
    _review(tmp_path)
    result = _review(
        tmp_path,
        outcome="progress",
        evidence_paths=["evidence/recon/response.txt"],
    )
    assert result["count"] == 0
    assert not result["warning"]


def test_evidence_paths_reset_counter_even_with_blank_outcome(tmp_path) -> None:
    _review(tmp_path)
    _review(tmp_path)
    result = _review(
        tmp_path,
        outcome="",
        evidence_paths=["evidence/recon/response.txt"],
    )
    assert result["count"] == 0
    assert not result["warning"]


def test_five_fresh_evidence_reviews_never_engage_the_lock(tmp_path) -> None:
    for number in range(5):
        result = _review(
            tmp_path,
            outcome="progress",
            evidence_paths=[f"evidence/recon/response-{number}.txt"],
        )
        assert result["count"] == 0, f"review {number} should reset the counter"
        assert not result["warning"]
        assert not result["locked"]
    assert state.semantic_lock(tmp_path) is None


def test_repeating_an_old_evidence_path_still_counts_as_unproductive(tmp_path) -> None:
    shared = ["evidence/recon/response.txt"]
    _review(tmp_path, outcome="progress", evidence_paths=shared)
    for number in range(5):
        result = _review(tmp_path, outcome="progress", evidence_paths=shared)
        assert result["count"] == number + 1
        assert result["locked"] is (number == 4), f"lock state wrong at iteration {number}"
    assert state.semantic_lock(tmp_path) is not None


_FINDING = {
    "created_at": "2026-09-23T10:54:32.038013+00:00",
    "engagement_id": "benchmark-run-test",
    "evidence_paths": ["evidence/recon/login.txt"],
    "execution_ids": [],
    "finding_id": "FIND-001",
    "receipt_paths": ["evidence/receipts/review-1.json"],
    "schema_version": 1,
    "severity": "Critical",
    "status": "validated",
    "summary": "Default credentials accepted at POST /api/v1/auth/login.",
    "title": "Default administrative credentials accepted at login",
}


def _record_finding(eng, title):
    """File one canonical finding record the way the store does."""
    directory = eng / "evidence"
    directory.mkdir(parents=True, exist_ok=True)
    with (directory / "findings.jsonl").open("a", encoding="utf-8") as handle:
        handle.write(json.dumps({**_FINDING, "title": title}) + "\n")


def test_new_findings_keep_prose_outcome_reviews_productive(tmp_path) -> None:
    """A batch that filed a finding is progress even when it describes it in prose."""
    for index in range(6):
        _review(tmp_path, outcome=f"H-00{index} confirmed; H-01{index} rejected (401)")
        _record_finding(tmp_path, f"Finding {index}: endpoint /api/v1/thing{index} vulnerable")
    assert state.semantic_lock(tmp_path) is None
    assert not _review(tmp_path)["warning"]


def test_new_finding_resets_a_counter_that_re_cited_evidence_grew(tmp_path) -> None:
    """Re-citing an already-seen path must not mask a newly filed finding."""
    shared = ["evidence/recon/batch-one.json"]
    # The first review is genuinely novel; the five that follow re-cite the same path.
    for _ in range(6):
        _review(tmp_path, outcome="reviewed", evidence_paths=shared)
    assert state.semantic_lock(tmp_path)
    _record_finding(tmp_path, "Finding filed after the re-cited reviews")
    result = _review(tmp_path, outcome="reviewed", evidence_paths=shared)
    assert result["count"] == 0
    assert state.semantic_lock(tmp_path) is None
