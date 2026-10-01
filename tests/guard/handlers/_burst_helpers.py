"""Shared engagement and executor fixtures for burst and target handler tests."""

import subprocess
import sys
import uuid
from pathlib import Path

import pytest

from plugins.violin_guard.core.engagement import bootstrap, ptt, state
from plugins.violin_guard.engine import execution
from tests.guard.receipt_fixture import bind_active_task

ROOT = Path(__file__).resolve().parents[3]

_SCOPE = """targets:
  ip_addresses: ["10.10.10.10"]
  in_scope_urls: ["http://10.10.10.10"]
  roles:
    web: 10.10.10.10
exclusions: {}
assessment_hosts:
  callback_hosts: [listener.example]
research_hosts: [github.com]
authorized_parties: ["test owner"]
authorisation:
  confirmed: true
rules_of_engagement:
  allowed_actions: [recon, vuln-research, exploitation]
  forbidden_actions: []
engagement:
  name: burst-test
  date: "2026-07-08"
  type: authorised-pentest
  client: test
"""


def _run(*args):
    return subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "violin_guard.py"), *args],
        capture_output=True,
        text=True,
    )


@pytest.fixture
def eng(tmp_path):
    d = tmp_path / "10.10.10.10-2026-07-08"
    assert bootstrap.init_engagement(str(d), host="10.10.10.10") == 0
    (d / "scope" / "scope.yaml").write_text(_SCOPE, encoding="utf-8")
    (d / "state" / ".skill-loaded-ts").write_text(
        "skill-loaded: skills/pentest/SKILL.md\nsession: ts\n", encoding="utf-8"
    )
    ptt = d / "state" / "ptt.md"
    ptt.write_text(
        ptt.read_text(encoding="utf-8").replace("| PT-010 | [ ] |", "| PT-010 | [~] |"),
        encoding="utf-8",
    )
    bind_active_task(d, "ts")
    return d


def _patch_burst(monkeypatch, eng_dir):
    """Run handle_exec_burst in-process: the real check-command gate is used for
    scope/destructive enforcement, but the executor is mocked so no real nmap/
    gobuster runs. Returns a recorder of executed commands."""
    rec = {"commands": [], "batch_id": None}

    # Batched approval: a pending-sync REVIEW is overridden (yolo) just like the
    # real CLI burst, so multi-command batches pass once in-scope. Destructive
    # hard-BLOCKs still cannot be overridden (service.py enforces that first).
    monkeypatch.setenv("HERMES_YOLO_MODE", "1")

    def fake_execute(command, *, eng_dir=eng_dir, phase, **kwargs):
        rec["commands"].append(command)
        active = ptt.find_active_task(ptt.parse_ptt(Path(eng_dir) / "state" / "ptt.md"))
        reservation_id = kwargs.get("sync_reservation")
        remaining = state.commit_execution_start(
            eng_dir,
            command,
            phase,
            active.id if active else "",
            str(uuid.uuid4()),
            reservation_id,
        )[0]
        rec["batch_id"] = state.get_pending_sync(eng_dir)
        return {
            "execution_id": "00000000-0000-0000-0000-000000000001",
            "status": "completed",
            "backend": kwargs.get("backend", "local"),
            "command": command,
            "phase": phase,
            "executed": True,
            "started_at": "2026-07-11T00:00:00Z",
            "completed_at": "2026-07-11T00:00:01Z",
            "exit_code": 0,
            "timed_out": False,
            "cancelled": False,
            "stdout_preview": "",
            "stderr_preview": "",
            "evidence_paths": {},
            "sync_required": remaining <= 0,
            "sync_credit_remaining": remaining,
            "sync_reservation_consumed": bool(reservation_id),
        }

    monkeypatch.setattr(execution, "execute", fake_execute)
    return rec
