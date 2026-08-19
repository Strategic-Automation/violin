"""Violin Guard — Core correctness and execution boundary tests.

Covers the explicit correctness criteria:
  - hard BLOCK (out-of-scope, destructive pattern) never creates a process;
  - POST_EXPLOITATION shares the same scope/skill-load/sync checks as EXPLOITATION;
  - backward compatibility: existing callers may ignore additive fields.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from plugins.violin_guard import handlers as TOOLS
from plugins.violin_guard.core import bootstrap, ptt
from plugins.violin_guard.engine import execution
from plugins.violin_guard.gates import command
from tests.guard.receipt_fixture import bind_active_task


def test_plugin_root_exposes_only_registration_contract() -> None:
    from plugins import violin_guard as plugin

    assert plugin.__all__ == ["REGISTERED_TOOLS", "TOOL_DEFINITIONS", "ToolDefinition", "register"]
    assert not hasattr(plugin, "bootstrap")


def _init_e2e(tmp_path, skill_file, allowed=("recon", "vuln-research", "exploitation")):
    """guard-clean engagement with scope + skill-load marker + advanced PTT."""
    scope = (
        "targets:\n"
        "  ip_addresses: [10.10.10.10]\n"
        "  in_scope_urls: []\n"
        "exclusions: {}\n"
        "authorized_parties: [test-owner]\n"
        "authorisation:\n"
        "  confirmed: true\n"
        "rules_of_engagement:\n"
        f"  allowed_actions: [{', '.join(allowed)}]\n"
        "  forbidden_actions: []\n"
        "engagement:\n"
        "  name: e2e-test\n"
        '  date: "2026-07-08"\n'
        "  type: authorised-pentest\n"
        "  client: test\n"
    )
    eng = tmp_path / "10.10.10.10-2026-07-08"
    assert bootstrap.init_engagement(str(eng), host="10.10.10.10") == 0
    (eng / "scope" / "scope.yaml").write_text(scope, encoding="utf-8")
    canonical = eng / "state" / f".skill-loaded-{skill_file.name.removeprefix('.skill-loaded-')}"
    canonical.write_text(
        f"skill-loaded: skills/pentest/SKILL.md\nsession: {skill_file.name}\n",
        encoding="utf-8",
    )
    ptt_doc = eng / "state" / "ptt.md"
    ptt_doc.write_text(
        ptt_doc.read_text(encoding="utf-8").replace("| PT-010 | [ ] |", "| PT-010 | [~] |"),
        encoding="utf-8",
    )
    bind_active_task(eng, "ts")
    return eng


# Module-level sentinel populated by the autouse fixture below. Hard-block
# tests assert this stays False (executor.execute is never reached).
FAKE_EXEC = {"called": False, "command": None}


@pytest.fixture(autouse=True)
def _fake_target_executor(monkeypatch):
    """Keep guard-state tests independent from installed network tools.

    The fake records whether executor.execute was ever reached. The
    hard-block tests below assert it is NOT reached.
    """
    FAKE_EXEC["called"] = False
    FAKE_EXEC["command"] = None

    def fake_execute(command, *, eng_dir, phase, **kwargs):
        FAKE_EXEC["called"] = True
        FAKE_EXEC["command"] = command
        active = ptt.find_active_task(ptt.parse_ptt(Path(eng_dir) / "state" / "ptt.md"))
        remaining = execution._commit_guard_state(
            Path(eng_dir), command, phase, active.id if active else ""
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
    yield
    FAKE_EXEC["called"] = False
    FAKE_EXEC["command"] = None


# --------------------------------------------------------------------------- #
# Correctness: hard BLOCK never spawns a process
# --------------------------------------------------------------------------- #
def test_hard_block_out_of_scope_never_executes(monkeypatch, tmp_path):
    """An out-of-scope target is a hard BLOCK -> violin_exec returns 'denied'
    with executed=False and executor.execute is never reached."""
    monkeypatch.setenv("HERMES_YOLO_MODE", "1")  # yolo can't bypass hard blocks
    skill_file = tmp_path / ".skill-loaded-ts"
    eng = _init_e2e(tmp_path, skill_file)
    d = str(eng)

    base = dict(
        eng_dir=d,
        scope=str(eng / "scope" / "scope.yaml"),
        phase="recon",
        skill_loaded_file=str(skill_file),
        session_id="ts",
    )
    ok = json.loads(TOOLS.handle_exec({**base, "command": "nmap -sV 10.10.10.10"}))
    assert ok["status"] in ("approved", "review", "ok"), ok

    FAKE_EXEC["called"] = False
    FAKE_EXEC["command"] = None

    blocked = json.loads(TOOLS.handle_exec({**base, "command": "nmap -sV 10.10.10.99"}))
    assert blocked["status"] == "denied", blocked
    assert blocked["executed"] is False
    assert FAKE_EXEC["called"] is False


def test_destructive_pattern_blocked_without_execution(monkeypatch, tmp_path):
    """Dangerous-pattern hard blocks never reach the executor, even in yolo."""
    monkeypatch.setenv("HERMES_YOLO_MODE", "1")
    skill_file = tmp_path / ".skill-loaded-ts"
    eng = _init_e2e(tmp_path, skill_file)
    d = str(eng)
    blocked = json.loads(
        TOOLS.handle_exec(
            {
                "eng_dir": d,
                "scope": str(eng / "scope" / "scope.yaml"),
                "phase": "recon",
                "command": "rm -rf /",
                "skill_loaded_file": str(skill_file),
                "session_id": "ts",
            }
        )
    )
    assert blocked["status"] == "denied", blocked
    assert blocked["executed"] is False
    assert FAKE_EXEC["called"] is False


def test_post_exploitation_requires_scope_and_skill_load(tmp_path):
    """POST_EXPLOITATION shares the target-touching gate: out-of-scope target
    is rejected and the skill-load gate still applies. It also requires an
    active hypothesis (like exploitation), so one is seeded here."""
    import datetime as _dt
    from datetime import UTC as _UTC

    skill_file = tmp_path / ".skill-loaded-ts"
    eng = _init_e2e(tmp_path, skill_file, allowed=("recon", "exploitation", "post-exploitation"))

    ts = _dt.datetime.now(_UTC).strftime("%Y-%m-%d %H:%M")
    (eng / "hypotheses.md").write_text(
        (eng / "hypotheses.md").read_text(encoding="utf-8")
        + (
            f"\n### H-001: Post-exploit persistence\n- **Status:** Candidate\n"
            f"- **Phase:** POST_EXPLOITATION\n- **Target:** 10.10.10.10\n"
            f"- **CVE Research:** web_search persistence CVE; NVD; not applicable\n"
            f"- **Exploit Research:** web_search persistence technique; vendor docs; no results\n"
            f"- **Updated:** {ts} UTC\n"
        ),
        encoding="utf-8",
    )
    ptt_path = eng / "state" / "ptt.md"
    ptt_path.write_text(
        ptt_path.read_text(encoding="utf-8")
        .replace("| PT-010 | [~] |", "| PT-010 | [x] |")
        .replace("| PT-042 | [ ] |", "| PT-042 | [~] |"),
        encoding="utf-8",
    )
    bind_active_task(eng, "ts")

    res = command.check_command(
        command.CheckCommandArgs(
            command="cat /etc/shadow",
            phase="post-exploitation",
            eng_dir=str(eng),
            scope=str(eng / "scope" / "scope.yaml"),
            session_id="ts",
        )
    )
    assert not res.errors, f"in-scope post-exploitation must pass core gate: {res.errors}"

    res_oob = command.check_command(
        command.CheckCommandArgs(
            command="nmap -sV 10.10.10.99",
            phase="post-exploitation",
            eng_dir=str(eng),
            scope=str(eng / "scope" / "scope.yaml"),
            session_id="ts",
        )
    )
    assert res_oob.errors, "post-exploitation out-of-scope must be rejected"


# --------------------------------------------------------------------------- #
# Correctness: migration — existing callers may ignore additive fields
# --------------------------------------------------------------------------- #
def test_exec_response_is_migration_safe(monkeypatch, tmp_path):
    """handle_exec's approved response carries additive fields
    (schema_version, execution_id, evidence_paths). Legacy callers that only
    read status/exit_code/stdout keep working."""
    monkeypatch.setenv("HERMES_YOLO_MODE", "1")
    skill_file = tmp_path / ".skill-loaded-ts"
    eng = _init_e2e(tmp_path, skill_file)
    d = str(eng)
    out = json.loads(
        TOOLS.handle_exec(
            {
                "eng_dir": d,
                "scope": str(eng / "scope" / "scope.yaml"),
                "phase": "recon",
                "command": "nmap -sV 10.10.10.10",
                "skill_loaded_file": str(skill_file),
                "session_id": "ts",
            }
        )
    )
    assert out["status"] in ("approved", "review", "ok")
    assert out["schema_version"] == 2
    assert "execution_id" in out and isinstance(out["execution_id"], str)
    assert "evidence_paths" in out and isinstance(out["evidence_paths"], dict)
    legacy_ok = out["status"] in ("approved", "review", "ok", "denied", "sync_required")
    assert legacy_ok
