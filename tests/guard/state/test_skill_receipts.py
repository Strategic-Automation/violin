"""Receipt-store behaviour is tested before any execution gate consumes it."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from plugins.violin_guard.skill_receipts import (
    HermesSkillViewAdapter,
    SkillViewResult,
    advance_context_generation,
    bind_task,
    complete_delivery,
    get_binding,
    get_delivery,
    prepare_delivery,
    prepare_review_readiness,
)


def _reserve(eng: Path, **overrides):
    values = {
        "session_id": "session-a",
        "skill": "pentest",
        "bundle_digest": "sha256:" + "a" * 64,
        "phase": "recon",
    }
    values.update(overrides)
    return prepare_delivery(eng, **values)


def _deliver(eng: Path, **overrides):
    reservation = _reserve(eng, **overrides)
    assert reservation.owner
    return complete_delivery(
        eng, reservation, SkillViewResult(True, content="# Skill"), delivered_turn_id="turn-1"
    )


def test_first_delivery_then_reuse(tmp_path: Path) -> None:
    first = _reserve(tmp_path)
    assert first.owner and first.status == "preparing"
    delivered = complete_delivery(tmp_path, first, SkillViewResult(True, content="# Skill"))
    reused = _reserve(tmp_path)

    assert delivered.status == "delivered"
    assert not reused.owner and reused.status == "delivered"


def test_concurrent_duplicate_only_has_one_owner(tmp_path: Path) -> None:
    first = _reserve(tmp_path)
    duplicate = _reserve(tmp_path)

    assert first.owner
    assert not duplicate.owner
    assert duplicate.id == first.id
    assert duplicate.status == "preparing"


def test_context_reset_requires_a_new_delivery(tmp_path: Path) -> None:
    old = _deliver(tmp_path)
    assert advance_context_generation(tmp_path, "session-a") == 1
    new = _reserve(tmp_path)

    assert new.owner
    assert new.id != old.id
    assert new.context_generation == 1


def test_digest_change_requires_a_new_delivery(tmp_path: Path) -> None:
    old = _deliver(tmp_path)
    new = _reserve(tmp_path, bundle_digest="sha256:" + "b" * 64)

    assert new.owner
    assert new.id != old.id


def test_failed_delivery_can_be_retried(tmp_path: Path) -> None:
    first = _reserve(tmp_path)
    failed = complete_delivery(tmp_path, first, SkillViewResult(False, error="missing"))
    retry = _reserve(tmp_path)

    assert failed.status == "failed"
    assert retry.owner
    assert get_delivery(tmp_path, retry.id)["attempts"] == 2


def test_corrupted_state_recovers_without_trusting_old_bindings(tmp_path: Path) -> None:
    state_path = tmp_path / "state" / "skills.json"
    state_path.parent.mkdir()
    state_path.write_text("{broken", encoding="utf-8")

    reservation = _reserve(tmp_path)
    data = json.loads(state_path.read_text(encoding="utf-8"))

    assert reservation.owner
    assert data["recovered_at"]
    assert data["bindings"] == {}


def test_binding_requires_delivered_receipt_and_carries_hypothesis(tmp_path: Path) -> None:
    pending = _reserve(tmp_path)
    with pytest.raises(ValueError, match="delivered"):
        bind_task(tmp_path, task_id="PT-001", delivery_id=pending.id)

    delivery = complete_delivery(tmp_path, pending, SkillViewResult(True, content="# Skill"))
    binding = bind_task(
        tmp_path,
        task_id="PT-001",
        delivery_id=delivery.id,
        hypothesis_id="H-001",
        technique="http probe",
    )

    assert binding["hypothesis_id"] == "H-001"
    assert get_binding(tmp_path, "PT-001") == binding


def test_review_readiness_is_evidence_specific(tmp_path: Path) -> None:
    receipt = _deliver(
        tmp_path,
        skill="fp-check",
        phase="retrospective",
        bundle_digest="sha256:" + "f" * 64,
    )
    first = prepare_review_readiness(
        tmp_path, finding_id="FIND-001", evidence_digest="sha256:e1", delivery_id=receipt.id
    )
    second = prepare_review_readiness(
        tmp_path, finding_id="FIND-001", evidence_digest="sha256:e2", delivery_id=receipt.id
    )

    assert first["evidence_digest"] != second["evidence_digest"]


def test_adapter_returns_structured_success_and_failure() -> None:
    success = HermesSkillViewAdapter(
        lambda *_args, **_kwargs: '{"success": true, "content": "body", "path": "x"}'
    )
    failure = HermesSkillViewAdapter(
        lambda *_args, **_kwargs: '{"success": false, "error": "not installed"}'
    )

    assert success.view("pentest").ready
    assert failure.view("pentest").error == "not installed"
