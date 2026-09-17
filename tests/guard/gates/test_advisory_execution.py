"""Warning prose cannot bypass a required guard review."""

import json

import pytest

from plugins.violin_guard.gates.command import CheckResult
from plugins.violin_guard.gates.terminal_policy import block_terminal_command
from plugins.violin_guard.handlers import exec_handlers


@pytest.mark.parametrize(
    "warning", ["hint: review required", "execution still allowed", "execution may proceed"]
)
def test_review_warning_never_becomes_permission(monkeypatch, warning):
    monkeypatch.delenv("HERMES_YOLO_MODE", raising=False)
    result = CheckResult(warnings=[warning], hints=["advisory only"])
    monkeypatch.setattr(exec_handlers, "_check_command_internal", lambda args: result)
    response = json.loads(exec_handlers.handle_exec({}))
    assert response["status"] == "denied"
    assert response["executed"] is False


def test_import_probe_does_not_allow_following_network_code():
    assert block_terminal_command(
        "python3 -c 'import socket; socket.create_connection((host, port))'"
    )
    assert block_terminal_command(
        "python3 -c 'from socket import create_connection; create_connection((host, port))'"
    )
    assert block_terminal_command("python3 -c 'from socket import create_connection'") is None
