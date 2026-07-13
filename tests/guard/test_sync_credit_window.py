"""Regression coverage for the executor-owned bounded sync window."""

from __future__ import annotations

import json
from pathlib import Path

from plugins.violin_guard.core import bootstrap, execution, service, state


def _engagement(tmp_path: Path) -> Path:
    eng = tmp_path / "10.10.10.10-2026-07-13"
    assert bootstrap.init_engagement(eng, host="10.10.10.10") == 0
    scope_path = eng / "scope" / "scope.yaml"
    scope_path.write_text(
        scope_path.read_text(encoding="utf-8").replace("confirmed: false", "confirmed: true"),
        encoding="utf-8",
    )
    (eng / "state" / ".skill-loaded-test").write_text("skill-loaded: test\n", encoding="utf-8")
    ptt_path = eng / "state" / "ptt.md"
    ptt_path.write_text(
        ptt_path.read_text(encoding="utf-8").replace("| PT-010 | [ ] |", "| PT-010 | [~] |"),
        encoding="utf-8",
    )
    return eng


def test_network_clients_are_not_local_bookkeeping() -> None:
    """Target-facing network tools must always arm review state."""
    for command in ("curl https://10.10.10.10", "dig 10.10.10.10", "host 10.10.10.10"):
        assert not state.is_local_bookkeeping_command(command)
    assert state.is_local_bookkeeping_command("echo local-note")


def test_five_commands_run_without_yolo_then_sixth_blocks(monkeypatch, tmp_path: Path) -> None:
    """The bounded window is an allowance, not five REVIEW responses."""
    eng = _engagement(tmp_path)

    def fake_execute(command: str, *, eng_dir: str, phase: str, **_kwargs):
        remaining = execution._commit_guard_state(Path(eng_dir), command, phase)
        return {
            "status": "completed",
            "executed": True,
            "exit_code": 0,
            "sync_required": remaining <= 0,
            "sync_credit_remaining": remaining,
            "evidence_paths": {},
        }

    monkeypatch.setattr(execution, "execute", fake_execute)
    args = {
        "eng_dir": str(eng),
        "scope": str(eng / "scope" / "scope.yaml"),
        "phase": "recon",
        "session_id": "test",
    }

    for port in range(1, state.DEFAULT_SYNC_CREDIT + 1):
        result = json.loads(service.handle_exec({**args, "command": f"nmap -p {port} 10.10.10.10"}))
        assert result["status"] == "ok", result

    sixth = json.loads(service.handle_exec({**args, "command": "nmap -p 99 10.10.10.10"}))
    assert sixth["status"] == "sync_required", sixth
