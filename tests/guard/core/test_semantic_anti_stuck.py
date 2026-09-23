"""Deterministic semantic no-progress counters and unlock requirements."""

from __future__ import annotations

from plugins.violin_guard.core import state


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
        "research_attempted": False,
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

    assert _review(tmp_path, research_attempted=True)["locked"]
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
