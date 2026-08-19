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
