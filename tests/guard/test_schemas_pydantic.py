"""Unit tests for Pydantic v2 schemas and validation models in plugins/violin_guard/schemas.py."""

import pytest
from pydantic import ValidationError

from plugins.violin_guard import schemas


def test_check_command_args_model_valid():
    raw = {
        "eng_dir": "/tmp/eng",
        "phase": "RECON",
        "command": "nmap 10.0.0.1",
        "target": "10.0.0.1",
    }
    model = schemas.validate_args(schemas.CheckCommandArgsModel, raw)
    assert model.eng_dir == "/tmp/eng"
    assert model.phase == "RECON"
    assert model.command == "nmap 10.0.0.1"
    assert model.target == "10.0.0.1"
    assert model.scope == ""


def test_check_command_args_model_invalid_missing_required():
    raw = {"eng_dir": "/tmp/eng"}
    with pytest.raises(ValidationError):
        schemas.validate_args(schemas.CheckCommandArgsModel, raw)


def test_check_command_args_model_extra_forbid():
    raw = {
        "eng_dir": "/tmp/eng",
        "phase": "RECON",
        "command": "nmap 10.0.0.1",
        "target": "10.0.0.1",
        "unsupported_extra_field": 123,
    }
    with pytest.raises(ValidationError):
        schemas.validate_args(schemas.CheckCommandArgsModel, raw)


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
    assert schemas.CHECK_COMMAND_SCHEMA["parameters"]["type"] == "object"
    assert "eng_dir" in schemas.CHECK_COMMAND_SCHEMA["parameters"]["required"]
    assert schemas.EXEC_BURST_SCHEMA["name"] == "violin_exec_burst"
    assert schemas.TARGET_SCHEMA["name"] == "violin_target"


def test_ffuf_wordlist_is_portably_optional():
    model = schemas.validate_args(
        schemas.FfufArgsModel,
        {
            "eng_dir": "/tmp/eng",
            "phase": "RECON",
            "target": "https://target.example/FUZZ",
        },
    )
    assert model.url == ""
    assert model.wordlist == ""


def test_review_batch_keeps_the_active_task_by_default():
    model = schemas.validate_args(
        schemas.ReviewBatchArgsModel,
        {"eng_dir": "/tmp/eng", "id": "PT-001", "note": "Reviewed batch evidence"},
    )
    assert model.status == "[~]"
