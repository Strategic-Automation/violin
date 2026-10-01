from __future__ import annotations

import subprocess
import uuid
from pathlib import Path

import pytest

from plugins.violin_guard.core.engagement import bootstrap, ptt, state
from plugins.violin_guard.core.evidence import history
from plugins.violin_guard.engine import execution
from tests.guard.receipt_fixture import bind_active_task

_PLATFORM_SCOPE = """targets:
  ip_addresses: ["10.10.10.10"]
  in_scope_urls: []
exclusions: {}
research_hosts: [services.nvd.nist.gov, api.osv.dev]
authorized_parties: ["test owner"]
authorisation:
  confirmed: true
rules_of_engagement:
  allowed_actions: [recon, vuln-research, exploitation]
  forbidden_actions: []
engagement:
  name: e2e-test
  date: "2026-07-08"
  type: authorised-pentest
  client: test
"""


def _cp(code, out="", err=""):
    """A fake CompletedProcess-like object returned by monkeypatched subprocess.run."""
    return lambda *a, **k: _FakeProc(code, out, err)


class _FakeProc:
    """Stand-in for subprocess.CompletedProcess used by monkeypatched run_guard."""

    def __init__(self, returncode, stdout="", stderr=""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


def _patch(monkeypatch, proc):
    monkeypatch.setattr(subprocess, "run", proc)


@pytest.fixture(autouse=True)
def _fake_target_executor(monkeypatch):
    """Keep guard-state tests independent from installed network tools."""

    def fake_execute(command, *, eng_dir, phase, **kwargs):
        engagement = Path(eng_dir)
        history.append_history(engagement, command, phase, 0, "evidence/executions/test.json")
        active = ptt.find_active_task(ptt.parse_ptt(engagement / "state" / "ptt.md"))
        remaining, _, _, _ = state.commit_execution_start(
            engagement, command, phase, active.id if active else "", str(uuid.uuid4())
        )
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
        }

    monkeypatch.setattr(execution, "execute", fake_execute)


def _init_e2e(tmp_path, skill_file):
    """Build a guard-clean RECON engagement (scope allows vuln-research so the
    hypothesis guard is exercised) and write the skill-load marker at its
    canonical location.

    The skill-load gate requires a session-scoped marker at
    ``$ENG_DIR/state/.skill-loaded-<session-id>``; passing ``--session-id``
    makes the CLI compute that canonical path itself, so we write there. We
    also pre-mark PT-010 as in-progress so the PTT phase gate (which BLOCKs
    until at least one PT row has moved past ``[ ]``) does not reject the very
    first recon command â€” this mirrors a normal SCOPING->RECON handoff.
    """
    eng = tmp_path / "10.10.10.10-2026-07-08"
    assert bootstrap.init_engagement(str(eng), host="10.10.10.10") == 0
    (eng / "scope" / "scope.yaml").write_text(_PLATFORM_SCOPE, encoding="utf-8")
    # Canonical marker path (session-id takes precedence over --skill-loaded-file).
    # The CLI builds ``$ENG_DIR/state/.skill-loaded-<session-id>`` from --session-id,
    # so the filename suffix is the bare session label, not the full marker name.
    canonical = eng / "state" / f".skill-loaded-{skill_file.name.removeprefix('.skill-loaded-')}"
    canonical.write_text(
        f"skill-loaded: skills/pentest/SKILL.md\nsession: {skill_file.name}\n",
        encoding="utf-8",
    )
    # At least one PTT row must have advanced so the staleness guard passes.
    ptt_path = eng / "state" / "ptt.md"
    ptt_path.write_text(
        ptt_path.read_text(encoding="utf-8").replace("| PT-010 | [ ] |", "| PT-010 | [~] |"),
        encoding="utf-8",
    )
    bind_active_task(eng, "ts")
    return eng


def _append_active_theories(path: Path, records: str) -> None:
    """Append fixture records inside the canonical hypothesis section."""
    source = path.read_text(encoding="utf-8")
    start = source.index("## Active Theories")
    end = source.find("\n## ", start + 1)
    if end < 0:
        end = len(source)
    updated = source[:end].rstrip() + "\n\n" + records.strip() + "\n\n" + source[end:].lstrip()
    path.write_text(updated, encoding="utf-8")
