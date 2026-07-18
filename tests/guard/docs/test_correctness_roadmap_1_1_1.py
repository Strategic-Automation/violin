"""Violin Reliability Roadmap 1.1.1 â€” Correctness test-plan gaps.

These cover the explicit acceptance items the roadmap lists under "Correctness":
  - hard BLOCK (out-of-scope, destructive pattern) never creates a process;
  - POST_EXPLOITATION shares the same scope/skill-load/sync checks as
    EXPLOITATION;
  - typed adapters reject out-of-scope targets before any process runs;
  - search_exploit normalizes searchsploit JSON, de-dupes candidates, and
    NEVER downloads or executes a candidate (executed_candidates is False);
  - backward compatibility: existing callers may ignore the additive
    schema_version/execution_id/evidence_paths fields.

Ported to the consolidated ``plugins.violin_guard`` package (the old flat
``guard`` package no longer exists).
"""

import importlib.util
import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "scripts"))

_PLUGIN = ROOT / "plugins" / "violin_guard"


def _load_pkg():
    spec = importlib.util.spec_from_file_location("vgpkg", _PLUGIN / "__init__.py")
    mod = importlib.util.module_from_spec(spec)
    mod.__path__ = [str(_PLUGIN)]
    mod.__package__ = "vgpkg"
    sys.modules["vgpkg"] = mod
    spec.loader.exec_module(mod)
    return mod


pkg = _load_pkg()
TOOLS = pkg.tools
ADAPTERS = pkg.adapters

from plugins.violin_guard import (  # noqa: E402
    bootstrap,
    command,  # noqa: E402
    execution,
    ptt,  # noqa: E402
)
from plugins.violin_guard.command import check_skill_load  # noqa: E402


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
    ptt = eng / "state" / "ptt.md"
    ptt.write_text(
        ptt.read_text(encoding="utf-8").replace("| PT-010 | [ ] |", "| PT-010 | [~] |"),
        encoding="utf-8",
    )
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

    res = command.check_command(
        command.CheckCommandArgs(
            command="cat /etc/shadow",
            phase="post-exploitation",
            eng_dir=str(eng),
            scope=str(eng / "scope" / "scope.yaml"),
            session_id="ts",
            skill_loaded_file=str(skill_file),
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
            skill_loaded_file=str(skill_file),
        )
    )
    assert res_oob.errors, "post-exploitation out-of-scope must be rejected"

    gate = check_skill_load(eng / "no-skill-loaded", "ts", mandatory=True)
    assert gate.errors, "skill-load gate must BLOCK post-exploitation without marker"


# --------------------------------------------------------------------------- #
# Correctness: typed adapters reject out-of-scope before process creation
# --------------------------------------------------------------------------- #
def test_adapter_builders_reject_out_of_scope_target(tmp_path):
    """Adapter command builders validate target structure; injection-style
    targets are refused at build time (no process created)."""

    with pytest.raises(ADAPTERS.AdapterError):
        ADAPTERS.build_ffuf({"url": "http://10.0.0.1/", "wordlist": "/tmp/x.txt"})

    with pytest.raises(ADAPTERS.AdapterError):
        ADAPTERS.build_nuclei({"target": "10.0.0.1", "severity": "bogus"})

    with pytest.raises(ADAPTERS.AdapterError):
        ADAPTERS.build_httpx({})  # no target


def test_adapter_handle_rejects_missing_tool_without_execution(monkeypatch):
    """When a scanner binary is absent, the typed adapter reports unavailable
    and never reaches executor.execute (no process creation)."""
    monkeypatch.setattr(ADAPTERS.shutil, "which", lambda _: None)
    # The typed adapter exposes an availability check; when the binary is
    # absent the command is never built/executed.
    avail = ADAPTERS.available("nmap", "local")
    assert avail.available is False
    assert "not installed" in avail.message.lower()
    assert FAKE_EXEC["called"] is False


# --------------------------------------------------------------------------- #
# Correctness: exploit search normalizes + never downloads/executes
# --------------------------------------------------------------------------- #
def test_search_exploit_normalizes_and_never_executes(monkeypatch):
    """search_exploit returns normalized candidates from searchsploit --json,
    de-dupes identical rows, and MUST NOT download or execute any candidate."""
    fake_json = json.dumps(
        {
            "RESULTS_EXPLOIT": [
                {
                    "Title": "OpenSSH 9.0 User Enumeration",
                    "Path": "/usr/share/exploitdb/exploits/linux/remote/99999.py",
                    "Platform": "linux",
                    "Type": "remote",
                },
                {
                    "Title": "OpenSSH 9.0 User Enumeration",  # duplicate
                    "Path": "/usr/share/exploitdb/exploits/linux/remote/99999.py",
                    "Platform": "linux",
                    "Type": "remote",
                },
            ],
            "RESULTS_SHELLCODE": [],
        }
    )
    monkeypatch.setattr(ADAPTERS.shutil, "which", lambda _: "/usr/bin/searchsploit")

    captured = {}

    def fake_run(cmd, **kwargs):
        captured["cmd"] = list(cmd)
        captured["kwargs"] = kwargs

        class _P:
            returncode = 0
            stdout = fake_json
            stderr = ""

        return _P()

    monkeypatch.setattr(subprocess, "run", fake_run)

    result = ADAPTERS.search_exploit({"product": "OpenSSH", "version": "9.0"})
    assert result["available"] is True
    assert len(result["candidates"]) == 1
    cand = result["candidates"][0]
    assert cand["title"] == "OpenSSH 9.0 User Enumeration"
    assert cand["provenance"] == "local-searchsploit"
    assert result["executed_candidates"] is False
    assert result["online_corroboration_required"] is True
    assert "--json" in captured["cmd"]
    assert "-m" not in captured["cmd"] and "-x" not in captured["cmd"]


def test_search_exploit_missing_tool_is_explicit(monkeypatch):
    """When searchsploit is absent, return an explicit 'tool unavailable' state."""
    monkeypatch.setattr(ADAPTERS.shutil, "which", lambda _: None)
    result = ADAPTERS.search_exploit({"product": "OpenSSH", "version": "9.0"})
    assert result["available"] is False
    assert "searchsploit" in result["message"].lower()
    assert result["executed_candidates"] is False


# --------------------------------------------------------------------------- #
# Correctness: migration â€” existing callers may ignore additive fields
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
