"""Unit tests for Pydantic v2 schemas and validation models in plugins/violin_guard/schemas.py."""

import pytest
from pydantic import ValidationError

from plugins.violin_guard.core import schemas


def test_exec_args_model_timeout_bounds():
    raw = {
        "eng_dir": "/tmp/eng",
        "phase": "RECON",
        "command": "nmap 10.0.0.1",
        "target": "10.0.0.1",
        "timeout_seconds": 9999,  # exceeds max 1800
    }
    with pytest.raises(ValidationError):
        schemas.validate_args(schemas.ExecArgsModel, raw)


def test_record_hypothesis_extra_forbidden():
    raw = {
        "eng_dir": "/tmp/eng",
        "custom_metadata": "allowed",
    }
    with pytest.raises(ValidationError):
        schemas.validate_args(schemas.RecordHypothesisArgsModel, raw)


def test_schema_exports_structure():
    assert schemas.EXEC_BURST_SCHEMA["name"] == "violin_exec_burst"
    assert schemas.TARGET_SCHEMA["name"] == "violin_target"


def test_review_batch_keeps_the_active_task_by_default():
    model = schemas.validate_args(
        schemas.ReviewBatchArgsModel,
        {"eng_dir": "/tmp/eng", "id": "PT-001", "note": "Reviewed batch evidence"},
    )
    assert model.status == "[~]"


def test_record_hypothesis_allows_research_attempted():
    model = schemas.validate_args(
        schemas.RecordHypothesisArgsModel,
        {"eng_dir": "/tmp/eng", "research_attempted": True},
    )
    assert model.research_attempted is True


@pytest.mark.parametrize(
    "model_type,required,default_status",
    [
        (
            schemas.RecordPttArgsModel,
            {"eng_dir": "eng", "id": "PT-001", "skill": "pentest", "technique": "recon"},
            "",
        ),
        (
            schemas.ReviewBatchArgsModel,
            {"eng_dir": "eng", "id": "PT-001", "note": "reviewed"},
            "[~]",
        ),
    ],
)
def test_review_payload_contract(model_type, required, default_status):
    first = model_type.model_validate(required)
    second = model_type.model_validate(required)
    assert first.status == default_status
    assert first.outcome == first.next_action == first.next_technique == ""
    assert first.research_attempted is False
    first.evidence_paths.append("evidence/recon/result.txt")
    assert second.evidence_paths == []
    payload = {
        **required,
        "outcome": "confirmed",
        "evidence_paths": ["evidence/recon/result.txt"],
        "next_action": "continue",
        "next_technique": "inspect",
        "research_attempted": True,
    }
    output = model_type.model_validate(payload).model_dump()
    assert all(output[key] == value for key, value in payload.items())
    with pytest.raises(ValidationError, match="extra_forbidden"):
        model_type.model_validate({**required, "unexpected": True})
    with pytest.raises(ValidationError):
        model_type.model_validate({**required, "evidence_paths": "not-a-list"})
    for key in required:
        with pytest.raises(ValidationError):
            model_type.model_validate(
                {name: value for name, value in required.items() if name != key}
            )


def test_exec_burst_publishes_the_session_binding_rule():
    """#186: the binding rule and where the id is read are published, not discovered."""
    description = schemas.EXEC_BURST_SCHEMA["description"]
    assert "different session" in description
    assert "violin_status.skill.session_id" in description
    field = schemas.ExecBurstArgsModel.model_fields["session_id"]
    assert "violin_status.skill.session_id" in (field.description or "")
