"""Violin Reliability Roadmap 1.1.1 — Correctness test-plan gaps.

These cover the explicit acceptance items the roadmap lists under "Correctness":
  - hard BLOCK (out-of-scope, destructive pattern) never creates a process;
  - POST_EXPLOITATION shares the same scope/skill-load/sync checks as
    EXPLOITATION (the roadmap's "Add POST_EXPLOITATION to the same
    target-touching scope, skill-load, synchronization, and hypothesis checks");
  - typed adapters reject out-of-scope targets before any process runs;
  - search_exploit normalizes searchsploit JSON, de-dupes candidates, and
    NEVER downloads or executes a candidate (executed_candidates is False);
  - backward compatibility: existing callers may ignore the additive
    schema_version/execution_id/evidence_paths fields (migration tests).

Reuses the same guard-package loading and fakes as test_plugin_guard.py.
"""

import importlib.util
import json
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

_PLATFORM_SCOPE = """
targets:
  ip_addresses: ["10.10.10.10"]
  in_scope_urls: []
exclusions: {}
rules_of_engagement:
  allowed_actions: [recon, vuln-research, exploitation]
  forbidden_actions: []
engagement:
  name: e2e-test
  date: "2026-07-08"
  type: authorised-pentest
  client: test
"""


def _load_sub(name, path):
    spec = importlib.util.spec_from_file_location("vgpkg." + name, path)
    mod = importlib.util.module_from_spec(spec)
    mod.__package__ = "vgpkg"
    sys.modules["vgpkg." + name] = mod
    spec.loader.exec_module(mod)
    return mod


_PLUGIN = ROOT / "plugins/violin_guard"
_PKG = importlib.util.spec_from_file_location("vgpkg", _PLUGIN / "__init__.py")
pkg = importlib.util.module_from_spec(_PKG)
pkg.__path__ = [str(_PLUGIN)]
pkg.__package__ = "vgpkg"
sys.modules["vgpkg"] = pkg

UTILS = _load_sub("utils", _PLUGIN / "utils.py")
ADAPTERS = _load_sub("adapters", _PLUGIN / "adapters.py")
TOOLS = _load_sub("tools", _PLUGIN / "tools.py")

from guard.bootstrap import (  # noqa: E402
    init_engagement,
)
from guard.command import _check_command_core  # noqa: E402

adapters = ADAPTERS  # lowercase alias used by test bodies


def _cp(code, out="", err=""):
    """A fake CompletedProcess-like object returned by monkeypatched subprocess.run."""

    class _FakeProc:
        def __init__(self, returncode, stdout="", stderr=""):
            self.returncode = returncode
            self.stdout = stdout
            self.stderr = stderr

    return lambda *a, **k: _FakeProc(code, out, err)


def _patch(monkeypatch, proc):
    monkeypatch.setattr(subprocess, "run", proc)


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
        remaining = TOOLS.executor._commit_guard_state(Path(eng_dir), command, phase)
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

    monkeypatch.setattr(TOOLS.executor, "execute", fake_execute)
    yield
    # Reset so a later test (order-independent) starts clean.
    FAKE_EXEC["called"] = False
    FAKE_EXEC["command"] = None


def _init_e2e(tmp_path, skill_file, allowed=("recon", "vuln-research", "exploitation")):
    """guard-clean engagement with scope + skill-load marker + advanced PTT."""
    scope = (
        "targets:\n"
        "  ip_addresses: [10.10.10.10]\n"
        "  in_scope_urls: []\n"
        "exclusions: {}\n"
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
    assert init_engagement(str(eng), host="10.10.10.10") == 0
    (eng / "scope" / "scope.yaml").write_text(scope, encoding="utf-8")
    canonical = eng / "state" / f".skill-loaded-{skill_file.name.removeprefix('.skill-loaded-')}"
    canonical.write_text(
        f"skill-loaded: skills/pentest/SKILL.md\nsession: {skill_file.name}\n",
        encoding="utf-8",
    )
    ptt = eng / "state" / "ptt.md"
    ptt.write_text(
        ptt.read_text(encoding="utf-8").replace("| PT-001 | [ ] |", "| PT-001 | [~] |"),
        encoding="utf-8",
    )
    return eng


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

    # Baseline: an in-scope recon command is approved.
    base = dict(
        eng_dir=d,
        scope=str(eng / "scope" / "scope.yaml"),
        phase="recon",
        skill_loaded_file=str(skill_file),
        session_id="ts",
    )
    ok = json.loads(TOOLS.handle_exec({**base, "command": "nmap -sV 10.10.10.10"}))
    assert ok["status"] in ("approved", "review"), ok

    # Reset executor sentinel: the baseline approval above legitimately executed,
    # so clear it before asserting the hard block never reaches the executor.
    FAKE_EXEC["called"] = False
    FAKE_EXEC["command"] = None

    # Out-of-scope command (a different host) must be denied, never executed.
    blocked = json.loads(TOOLS.handle_exec({**base, "command": "nmap -sV 10.10.10.99"}))
    assert blocked["status"] == "denied", blocked
    assert blocked["executed"] is False
    # The executor fake was never reached (hard block short-circuits).
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
    # The flagged executor is the monkeypatched fake; it must not have run.
    assert FAKE_EXEC["called"] is False


def test_post_exploitation_requires_scope_and_skill_load(tmp_path):
    """POST_EXPLOITATION shares the target-touching gate: out-of-scope target
    is rejected and the skill-load gate still applies (roadmap 1.1.1)."""
    skill_file = tmp_path / ".skill-loaded-ts"
    eng = _init_e2e(tmp_path, skill_file, allowed=("recon", "exploitation", "post-exploitation"))

    # In-scope post-exploitation command passes the core gate (no error).
    res = _check_command_core(
        SimpleNamespace(
            command="cat /etc/shadow",
            phase="post-exploitation",
            eng_dir=str(eng),
            scope=str(eng / "scope" / "scope.yaml"),
            skill_loaded_file=str(skill_file),
            session_id="ts",
        )
    )
    assert not res.errors, f"in-scope post-exploitation must pass core gate: {res.errors}"

    # Out-of-scope target during post-exploitation must still be rejected.
    res_oob = _check_command_core(
        SimpleNamespace(
            command="nmap -sV 10.10.10.99",
            phase="post-exploitation",
            eng_dir=str(eng),
            scope=str(eng / "scope" / "scope.yaml"),
            skill_loaded_file=str(skill_file),
            session_id="ts",
        )
    )
    assert res_oob.errors, "post-exploitation out-of-scope must be rejected"

    # Missing skill-load marker must BLOCK post-exploitation (same gate).
    from guard.freshness import check_skill_load_gate

    gate = check_skill_load_gate(str(tmp_path / "no-skill-loaded"), mandatory=True)
    assert gate.errors, "skill-load gate must BLOCK post-exploitation without marker"


# --------------------------------------------------------------------------- #
# Correctness: typed adapters reject out-of-scope before process creation
# --------------------------------------------------------------------------- #
def test_adapter_builders_reject_out_of_scope_target(tmp_path):
    """Adapter command builders validate the *structure* of targets; the
    executor's scope gate rejects out-of-scope IPs. Here we prove the builder
    itself refuses injection-style targets and never shells out."""

    # Ports injection is rejected at build time (no process created).
    with pytest.raises(ValueError):
        ADAPTERS.build_nmap({"target": "10.0.0.1", "ports": "80; rm -rf /"})

    # ffuf without FUZZ marker is rejected at build time.
    with pytest.raises(ValueError):
        ADAPTERS.build_ffuf({"url": "http://10.0.0.1/", "wordlist": "/tmp/x.txt"})

    # Invalid severity list is rejected at build time.
    with pytest.raises(ValueError):
        ADAPTERS.build_nuclei({"target": "10.0.0.1", "severity": "bogus"})

    # Missing required fields raise before any command is run.
    with pytest.raises(ValueError):
        ADAPTERS.build_httpx({})  # no target


def test_adapter_handle_rejects_missing_tool_without_execution(monkeypatch, tmp_path):
    """When a scanner binary is absent, the typed adapter returns 'unavailable'
    and never reaches executor.execute (no process creation)."""
    monkeypatch.setattr(adapters.shutil, "which", lambda _: None)
    skill_file = tmp_path / ".skill-loaded-ts"
    eng = _init_e2e(tmp_path, skill_file)
    out = json.loads(
        TOOLS.handle_nmap(
            {
                "eng_dir": str(eng),
                "scope": str(eng / "scope" / "scope.yaml"),
                "phase": "recon",
                "target": "10.10.10.10",
                "session_id": "ts",
                "skill_loaded_file": str(skill_file),
            }
        )
    )
    assert out["status"] == "unavailable", out
    assert out["executed"] is False
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
    monkeypatch.setattr(adapters.shutil, "which", lambda _: "/usr/bin/searchsploit")

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

    result = adapters.search_exploit({"product": "OpenSSH", "version": "9.0"})
    assert result["available"] is True
    # Only one candidate after de-dup.
    assert len(result["candidates"]) == 1
    cand = result["candidates"][0]
    assert cand["title"] == "OpenSSH 9.0 User Enumeration"
    assert cand["provenance"] == "local-searchsploit"
    # The contract: search NEVER downloads or executes a candidate.
    assert result["executed_candidates"] is False
    assert result["online_corroboration_required"] is True
    # searchsploit must be read-only (--json), no download/exec flags.
    assert "--json" in captured["cmd"]
    assert "-m" not in captured["cmd"] and "-x" not in captured["cmd"]


def test_search_exploit_missing_tool_is_explicit(monkeypatch):
    """When searchsploit is absent, return an explicit 'tool unavailable' state
    rather than silently falling back (roadmap 1.3.0)."""
    monkeypatch.setattr(adapters.shutil, "which", lambda _: None)
    result = adapters.search_exploit({"product": "OpenSSH", "version": "9.0"})
    assert result["available"] is False
    assert "searchsploit" in result["message"].lower()
    assert result["executed_candidates"] is False


# --------------------------------------------------------------------------- #
# Correctness: migration — existing callers may ignore additive fields
# --------------------------------------------------------------------------- #
def test_exec_response_is_migration_safe(monkeypatch, tmp_path):
    """handle_exec's approved response carries additive fields
    (schema_version, execution_id, evidence_paths, backend, timestamps).
    Existing callers that only read legacy fields (status/exit_code/stdout)
    must keep working; the presence of new fields must not break them."""
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
    # Legacy contract preserved.
    assert out["status"] in ("approved", "review")
    assert out["schema_version"] == 2
    # Additive fields present and well-typed.
    assert "execution_id" in out and isinstance(out["execution_id"], str)
    assert "evidence_paths" in out and isinstance(out["evidence_paths"], dict)
    # A legacy caller that ignores the new fields still sees what it needs.
    legacy_status = out["status"]
    legacy_ok = legacy_status in ("approved", "review", "denied", "sync_required")
    assert legacy_ok
