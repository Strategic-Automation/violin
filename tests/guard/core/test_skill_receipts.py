"""Receipt-store behaviour is tested before any execution gate consumes it."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from plugins.violin_guard.core.skills.skill_receipts import (
    HermesSkillViewAdapter,
    SkillViewResult,
    advance_context_generation,
    bind_task,
    binding_readiness,
    complete_delivery,
    finish_skill_view,
    get_binding,
    get_delivery,
    prepare_delivery,
    reserve_skill_view,
    skill_content_digest,
)

_SKILL_CONTENT = "# Skill"


def _reserve(eng: Path, **overrides):
    values = {
        "session_id": "session-a",
        "skill": "pentest",
        "content_digest": skill_content_digest(_SKILL_CONTENT),
        "phase": "recon",
    }
    values.update(overrides)
    return prepare_delivery(eng, **values)


def _deliver(eng: Path, **overrides):
    reservation = _reserve(eng, **overrides)
    assert reservation.owner
    return complete_delivery(
        eng,
        reservation,
        SkillViewResult(True, content=_SKILL_CONTENT),
        delivered_turn_id="turn-1",
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


def test_skill_view_slot_allows_one_concurrent_hermes_owner(tmp_path: Path) -> None:
    first = reserve_skill_view(tmp_path, session_id="session-a", skill="pentest", phase="recon")
    duplicate = reserve_skill_view(tmp_path, session_id="session-a", skill="pentest", phase="recon")

    assert first.owner
    assert not duplicate.owner
    assert duplicate.status == "preparing"

    finish_skill_view(tmp_path, first)
    next_view = reserve_skill_view(tmp_path, session_id="session-a", skill="pentest", phase="recon")
    assert next_view.owner


def test_expired_preparation_is_reclaimed_and_old_owner_cannot_complete(tmp_path: Path) -> None:
    first = _reserve(tmp_path, content_digest=skill_content_digest("# new"))
    state_path = tmp_path / "state" / "skills.json"
    data = json.loads(state_path.read_text(encoding="utf-8"))
    data["deliveries"][first.id]["expires_at"] = "2000-01-01T00:00:00Z"
    state_path.write_text(json.dumps(data), encoding="utf-8")

    reclaimed = _reserve(tmp_path, content_digest=skill_content_digest("# new"))
    assert reclaimed.owner
    assert reclaimed.owner_token != first.owner_token

    with pytest.raises(ValueError, match="stale"):
        complete_delivery(tmp_path, first, SkillViewResult(True, content="# old"))

    delivered = complete_delivery(tmp_path, reclaimed, SkillViewResult(True, content="# new"))
    assert delivered.status == "delivered"


def test_context_reset_requires_a_new_delivery(tmp_path: Path) -> None:
    old = _deliver(tmp_path)
    assert advance_context_generation(tmp_path, "session-a") == 1
    new = _reserve(tmp_path)

    assert new.owner
    assert new.id != old.id
    assert new.context_generation == 1


def test_digest_change_requires_a_new_delivery(tmp_path: Path) -> None:
    old = _deliver(tmp_path)
    new = _reserve(tmp_path, content_digest=skill_content_digest("# Changed Skill"))

    assert new.owner
    assert new.id != old.id


def test_delivery_rejects_content_that_does_not_match_reserved_digest(tmp_path: Path) -> None:
    reservation = _reserve(tmp_path)

    with pytest.raises(ValueError, match="does not match its reserved content digest"):
        complete_delivery(tmp_path, reservation, SkillViewResult(True, content="# Changed"))

    delivered = complete_delivery(
        tmp_path, reservation, SkillViewResult(True, content=_SKILL_CONTENT)
    )
    assert delivered.status == "delivered"
    assert get_delivery(tmp_path, delivered.id)["content_digest"] == skill_content_digest(
        _SKILL_CONTENT
    )


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


def test_schema_one_receipts_are_not_migrated_or_reused(tmp_path: Path) -> None:
    state_path = tmp_path / "state" / "skills.json"
    state_path.parent.mkdir()
    state_path.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "context": {"session_id": "session-a", "generation": 0},
                "deliveries": {"old": {"id": "old", "status": "delivered"}},
                "bindings": {"PT-001": {"delivery_id": "old"}},
            }
        ),
        encoding="utf-8",
    )

    binding, reason = binding_readiness(tmp_path, task_id="PT-001", session_id="session-a")
    reservation = _reserve(tmp_path)
    data = json.loads(state_path.read_text(encoding="utf-8"))

    assert binding is None
    assert "unavailable" in reason
    assert reservation.owner
    assert data["schema_version"] == 3
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


def test_fp_check_delivery_does_not_create_extra_review_state(tmp_path: Path) -> None:
    _deliver(
        tmp_path,
        skill="fp-check",
        phase="retrospective",
        content_digest=skill_content_digest(_SKILL_CONTENT),
    )
    data = json.loads((tmp_path / "state" / "skills.json").read_text(encoding="utf-8"))
    assert "review_readiness" not in data


def test_adapter_returns_structured_success_and_failure() -> None:
    success = HermesSkillViewAdapter(
        lambda *_args, **_kwargs: '{"success": true, "content": "body", "path": "x"}'
    )
    failure = HermesSkillViewAdapter(
        lambda *_args, **_kwargs: '{"success": false, "error": "not installed"}'
    )

    assert success.view("pentest").ready
    assert failure.view("pentest").error == "not installed"


def test_skill_preparation_rechecks_content_before_reusing_receipt(tmp_path: Path) -> None:
    from plugins.violin_guard.handlers.base import _prepare_skill_reservation_payload

    contents = iter(("# First", "# Updated", "# Updated"))

    class ChangingSkillAdapter:
        def view(self, *_args, **_kwargs):
            return SkillViewResult(True, content=next(contents))

    reservations = []
    digests = []
    for _ in range(3):
        reservation, digest, early_response = _prepare_skill_reservation_payload(
            tmp_path,
            skill="pentest",
            phase="recon",
            task_id="PT-001",
            adapter_cls=ChangingSkillAdapter,
        )
        reservations.append(reservation)
        digests.append(digest)
        if early_response is not None:
            assert json.loads(early_response)["status"] == "skill_prepared"

    assert digests == [
        skill_content_digest("# First"),
        skill_content_digest("# Updated"),
        skill_content_digest("# Updated"),
    ]
    assert reservations[0].id != reservations[1].id
    assert reservations[1].id == reservations[2].id
    assert reservations[2].status == "delivered"
