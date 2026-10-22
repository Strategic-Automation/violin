"""The violin_record_ptt schema must agree with the handler's note requirement."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from plugins.violin_guard.core import schemas


def test_schema_marks_lifecycle_note_required() -> None:
    schema = schemas.RECORD_PTT_SCHEMA
    properties = (
        schema["parameters"]["properties"] if "parameters" in schema else schema["properties"]
    )
    required = schema["parameters"]["required"] if "parameters" in schema else schema["required"]

    assert "note" in required
    assert properties["note"].get("description")


def test_model_rejects_a_blank_lifecycle_note() -> None:
    base = {"eng_dir": "eng", "id": "PT-001", "skill": "pentest", "technique": "recon"}

    with pytest.raises(ValidationError):
        schemas.RecordPttArgsModel.model_validate({**base})
    with pytest.raises(ValidationError):
        schemas.RecordPttArgsModel.model_validate({**base, "note": "   "})


def test_ptt_schema_explains_lifecycle_transition_requirements() -> None:
    status = schemas.RecordPttArgsModel.model_fields["status"].description or ""
    assert "Starting an untouched task requires '[~]'" in status
    assert "'[!]' blocked" in status
    assert "review/close transitions" in status
    assert "on every PTT update" in schemas.RecordPttArgsModel.model_fields["skill"].description
    assert "on every PTT update" in schemas.RecordPttArgsModel.model_fields["technique"].description
    assert (
        "start, update, or close"
        in schemas.RecordPttArgsModel.model_fields["hypothesis_id"].description
    )
