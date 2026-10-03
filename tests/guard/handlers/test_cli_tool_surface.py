"""Cli tool surface regression tests."""

import json
from pathlib import Path

import pytest

from plugins.violin_guard import handlers as service
from plugins.violin_guard import handlers as tools
from plugins.violin_guard.core.engagement import state
from tests.guard.handlers._burst_helpers import (
    ROOT,
    _run,
)
from tests.guard.handlers._burst_helpers import (
    eng as eng,
)
from tests.guard.receipt_fixture import bind_active_task


def test_public_handlers_serialize_expected_errors(tmp_path):
    cases = (
        (service.handle_status, {}),
        (
            service.handle_exec_status,
            {"eng_dir": str(tmp_path), "execution_id": "not-an-execution-id"},
        ),
    )

    for handler, args in cases:
        result = json.loads(handler(args))
        assert result["status"] == "error"
        assert result["error"]


def test_plugin_exposes_new_tools():
    import yaml

    names = (
        {t[0] for t in tools._TOOLS}
        if hasattr(tools, "_TOOLS")
        else set(n for n in dir(tools) if n.startswith("handle_"))
    )
    assert "handle_exec_burst" in names
    assert "handle_target" in names

    manifest = yaml.safe_load(
        (ROOT / "plugins" / "violin_guard" / "plugin.yaml").read_text(encoding="utf-8")
    )
    tool_names = set(manifest["provides_tools"])
    assert "violin_exec_burst" in tool_names
    assert "violin_target" in tool_names
    assert "violin_review_batch" in tool_names
    assert "violin_submit_finding" in tool_names
    assert (
        not {
            "violin_sync_done",
            "violin_review_and_release",
            "violin_finding",
        }
        & tool_names
    )


def test_status_skill_section_reports_load_state_and_exit_code(eng):
    state.record_session_id(eng, "ts")
    bind_active_task(eng, "ts")
    loaded = _run("status", "--eng-dir", str(eng), "--section", "skill")
    loaded_data = json.loads(loaded.stdout)
    assert loaded.returncode == 0
    assert loaded_data["binding_ready"] is True
    assert loaded_data["legacy_marker_status"] == "obsolete"

    marker = Path(loaded_data["legacy_marker"])
    marker.unlink()
    missing = _run("status", "--eng-dir", str(eng), "--section", "skill")
    missing_data = json.loads(missing.stdout)
    assert missing.returncode == 0
    assert missing_data["binding_ready"] is True
    assert missing_data["legacy_marker_status"] == "absent"


@pytest.mark.parametrize(
    "removed",
    [
        "review-and-release",
        "finding",
        "sync-done",
        "record-history",
        "message-tick",
        "skill-status",
        "check-skill-loaded",
    ],
)
def test_removed_cli_commands_are_absent(removed):
    result = _run(removed, "--help")
    assert result.returncode != 0
    assert "invalid choice" in result.stderr


def test_review_batch_cli_exposes_only_batch_lifecycle_fields():
    result = _run("review-batch", "--help")
    assert result.returncode == 0
    assert "--status" in result.stdout
    assert "--note" in result.stdout
    assert "--finding-title" not in result.stdout
