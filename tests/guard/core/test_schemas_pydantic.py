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


def test_record_hypothesis_accepts_numeric_confidence():
    model = schemas.validate_args(
        schemas.RecordHypothesisArgsModel,
        {"eng_dir": "/tmp/eng", "confidence": 0.9},
    )
    assert model.confidence == "0.9"
    str_model = schemas.validate_args(
        schemas.RecordHypothesisArgsModel,
        {"eng_dir": "/tmp/eng", "confidence": "0.9"},
    )
    assert str_model.confidence == model.confidence


def test_record_hypothesis_accepts_integer_port():
    model = schemas.validate_args(
        schemas.RecordHypothesisArgsModel,
        {"eng_dir": "/tmp/eng", "port": 443},
    )
    assert model.port == "443"


def test_record_hypothesis_normalises_variant_vuln_class():
    model = schemas.validate_args(
        schemas.RecordHypothesisArgsModel,
        {"eng_dir": "/tmp/eng", "vuln_class": "IDOR"},
    )
    assert model.vuln_class == "idor"


def test_record_hypothesis_normalizes_human_readable_vuln_classes():
    for value, expected in (
        ("Mass assignment", "mass-assignment"),
        ("Missing authentication", "missing-authentication"),
        ("IDOR access control", "idor-access-control"),
    ):
        model = schemas.validate_args(
            schemas.RecordHypothesisArgsModel,
            {"eng_dir": "/tmp/eng", "vuln_class": value},
        )
        assert model.vuln_class == expected


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("mass-assignmnt", "mass-assignment"),
        ("missing-auth", "missing-authentication"),
        ("xss-bypass", "xss"),
    ],
)
def test_record_hypothesis_rejects_unknown_vuln_class_with_suggestion(value: str, expected: str):
    with pytest.raises(ValidationError) as exc:
        schemas.validate_args(
            schemas.RecordHypothesisArgsModel,
            {"eng_dir": "/tmp/eng", "vuln_class": value},
        )
    message = str(exc.value)
    assert f"Did you mean '{expected}'?" in message
    assert message.index("Did you mean") < message.index("Valid classes are")


@pytest.mark.parametrize(
    ("value", "expected_suggestion"),
    (
        ("bogus-class", None),
        ("Default/weak credentials", "default-credentials"),
        ("bogus-injection", None),
    ),
)
def test_record_hypothesis_rejects_unknown_vuln_class_with_appropriate_suggestion(
    value: str, expected_suggestion: str | None
):
    with pytest.raises(ValidationError) as exc:
        schemas.validate_args(
            schemas.RecordHypothesisArgsModel,
            {"eng_dir": "/tmp/eng", "vuln_class": value},
        )
    message = str(exc.value)
    assert "unknown vuln_class" in message
    assert "Valid classes are" in message
    if expected_suggestion is None:
        assert "Did you mean" not in message
    else:
        assert f"Did you mean '{expected_suggestion}'?" in message


def test_record_hypothesis_accepts_coverage_table_vuln_class_names():
    for name in (
        "default-credentials",
        "idor-access-control",
        "jwt-attacks",
        "workflow-state-abuse",
    ):
        model = schemas.validate_args(
            schemas.RecordHypothesisArgsModel,
            {"eng_dir": "/tmp/eng", "vuln_class": name},
        )
        assert model.vuln_class == name


def test_record_hypothesis_publishes_the_vuln_class_enum():
    description = schemas.RecordHypothesisArgsModel.model_fields["vuln_class"].description or ""
    assert "idor" in description and "sqli" in description
    assert "mass-assignment" in description
    assert "missing-authentication" in description
    source_description = (
        schemas.RecordHypothesisArgsModel.model_fields["candidate_source"].description or ""
    )
    assert "api-enumeration" in source_description
    assert "api-enumeration is a technique-as-source alias for api-testing" in source_description


def test_record_hypothesis_accepts_evidence_paths_and_merges_runtime_evidence():
    model = schemas.validate_args(
        schemas.RecordHypothesisArgsModel,
        {
            "eng_dir": "/tmp/eng",
            "runtime_evidence": "evidence/recon/a.txt",
            "evidence_paths": ["evidence/recon/b.txt", "evidence/recon/a.txt"],
        },
    )
    assert model.evidence_paths == ["evidence/recon/b.txt", "evidence/recon/a.txt"]
    assert model.runtime_evidence == "evidence/recon/a.txt, evidence/recon/b.txt"


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
