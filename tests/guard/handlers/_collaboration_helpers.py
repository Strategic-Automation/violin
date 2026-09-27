"""Shared engagement setup for handler collaboration tests."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from plugins.violin_guard.core.engagement import bootstrap, state
from plugins.violin_guard.core.evidence import history
from tests.guard.receipt_fixture import bind_active_task


def _engagement(tmp_path: Path) -> Path:
    eng = tmp_path / "engagement"
    assert bootstrap.init_engagement(eng, host="10.10.10.10") == 0
    scope = eng / "scope" / "scope.yaml"
    scope.write_text(
        scope.read_text(encoding="utf-8").replace("confirmed: false", "confirmed: true"),
        encoding="utf-8",
    )
    ptt_path = eng / "state" / "ptt.md"
    ptt_path.write_text(
        ptt_path.read_text(encoding="utf-8").replace("| PT-010 | [ ] |", "| PT-010 | [~] |"),
        encoding="utf-8",
    )
    state.record_session_id(eng, "test-session")
    (eng / "state" / ".skill-loaded-test-session").write_text(
        "skill-loaded: pentest\n", encoding="utf-8"
    )
    bind_active_task(eng, "test-session")
    return eng


def _pending_batch(eng: Path) -> None:
    command = "nmap -sV 10.10.10.10"
    (eng / "evidence" / "executions").mkdir(parents=True, exist_ok=True)
    manifest = eng / "evidence" / "executions" / "batch-command.json"
    stdout = eng / "evidence" / "executions" / "batch-command.stdout.txt"
    stdout.write_text("80/tcp open http\n", encoding="utf-8")
    state.atomic_json(
        manifest,
        {
            "command": command,
            "phase": "RECON",
            "completed_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
            "exit_code": 0,
            "evidence_paths": {
                "manifest": manifest.relative_to(eng).as_posix(),
                "stdout": stdout.relative_to(eng).as_posix(),
            },
        },
    )
    history.append_history(eng, command, "RECON", 0, manifest.relative_to(eng).as_posix())
    state.mark_pending_sync(eng, command, "RECON", "PT-010")
