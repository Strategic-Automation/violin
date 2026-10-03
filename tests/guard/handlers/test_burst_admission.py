"""Burst admission regression tests."""

import json

import pytest

from plugins.violin_guard import handlers as service
from tests.guard.handlers._burst_helpers import (
    _patch_burst,
)
from tests.guard.handlers._burst_helpers import (
    eng as eng,
)


def test_exec_burst_missing_commands_file(eng):
    data = json.loads(
        service.handle_exec_burst(
            {
                "eng_dir": str(eng),
                "scope": str(eng / "scope" / "scope.yaml"),
                "phase": "recon",
                "commands_file": "does-not-exist.txt",
                "session_id": "ts",
                "skill_loaded_file": str(eng / "state" / ".skill-loaded-ts"),
            }
        )
    )
    assert data["status"] == "error", data
    assert "commands file not found" in data["error"], data


@pytest.mark.parametrize(
    "malformed",
    [
        # The JSON text of an array, not the array itself — an accidental
        # double-encoding that was previously executed as one shell command
        # (exit 127) with a receipt written for the non-burst.
        json.dumps(["nmap -sV 10.10.10.10", "gobuster dir -u http://10.10.10.10"]),
        # A list whose element is not a string.
        ["nmap -sV 10.10.10.10", 123],
    ],
    ids=["double-encoded-json-string", "non-string-element"],
)
def test_exec_burst_rejects_malformed_commands(eng, monkeypatch, malformed):
    """A commands argument that is not a list of strings is rejected before any
    command is admitted, so no receipt is written for the malformed burst.

    Previously the JSON text of an array was executed as one shell command, an
    accidental double-encoding that produced an exit-127 failure and still
    wrote a receipt. Admission now rejects the shape with the expected type
    named, before any command is executed or any receipt is created.
    """
    rec = _patch_burst(monkeypatch, str(eng))
    data = json.loads(
        service.handle_exec_burst(
            {
                "eng_dir": str(eng),
                "scope": str(eng / "scope" / "scope.yaml"),
                "phase": "recon",
                "commands": malformed,
                "session_id": "ts",
                "skill_loaded_file": str(eng / "state" / ".skill-loaded-ts"),
                "label": "malformed",
            }
        )
    )
    assert data["status"] == "error", data
    assert "list of strings" in data["error"], data
    # Rejected at admission: no command was executed, so no receipt is written.
    assert rec["commands"] == []
    assert list((eng / "evidence" / "executions").glob("*.json")) == []


def test_exec_burst_rejects_absolute_commands_file(eng):
    path = eng / "commands.txt"
    path.write_text("nmap -sV 10.10.10.10\n", encoding="utf-8")
    data = json.loads(
        service.handle_exec_burst(
            {
                "eng_dir": str(eng),
                "phase": "recon",
                "commands_file": str(path.resolve()),
                "session_id": "ts",
            }
        )
    )
    assert data["status"] == "error"
    assert "engagement-relative" in data["error"]


@pytest.mark.parametrize(
    ("relative", "content", "expected"),
    [
        ("../commands.txt", "echo safe\n", "escapes"),
        ("too-many.txt", "\n".join(f"echo {i}" for i in range(21)), "burst limit"),
    ],
)
def test_exec_burst_rejects_unsafe_command_files(eng, relative, content, expected):
    path = eng.parent / "commands.txt" if relative.startswith("..") else eng / relative
    path.write_text(content, encoding="utf-8")
    data = json.loads(
        service.handle_exec_burst(
            {"eng_dir": str(eng), "phase": "recon", "commands_file": relative}
        )
    )
    message = data.get("error") or data.get("reason") or ""
    assert expected in message


def test_exec_burst_rejects_oversized_command_file(eng):
    path = eng / "too-large.txt"
    path.write_text("x" * (64 * 1024 + 1), encoding="utf-8")
    data = json.loads(
        service.handle_exec_burst(
            {"eng_dir": str(eng), "phase": "recon", "commands_file": path.name}
        )
    )
    assert "exceeds" in data["error"]


def test_exec_burst_rejects_symlinked_commands_file(eng):
    target = eng / "real-commands.txt"
    link = eng / "linked-commands.txt"
    target.write_text("echo safe\n", encoding="utf-8")
    try:
        link.symlink_to(target)
    except OSError:
        pytest.skip("symlink creation is unavailable")
    data = json.loads(
        service.handle_exec_burst(
            {"eng_dir": str(eng), "phase": "recon", "commands_file": link.name}
        )
    )
    assert "symlink" in data["error"]
