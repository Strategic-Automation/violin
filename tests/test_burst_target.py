"""Regression tests for burst mode (violin_exec_burst) and violin_target.

These exercise the real CLI end-to-end (subprocess) so the argparse wiring,
dispatch, and scope-host resolution are covered, not just the in-process funcs.
"""

import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

from guard.bootstrap import init_engagement  # noqa: E402

_SCOPE = """targets:
  ip_addresses: ["10.10.10.10"]
  in_scope_urls: ["http://10.10.10.10"]
  roles:
    web: 10.10.10.10
exclusions: {}
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
    assert init_engagement(str(d), host="10.10.10.10") == 0
    (d / "scope" / "scope.yaml").write_text(_SCOPE, encoding="utf-8")
    (d / "state" / ".skill-loaded-ts").write_text(
        "skill-loaded: skills/pentest/SKILL.md\nsession: ts\n", encoding="utf-8"
    )
    ptt = d / "state" / "ptt.md"
    ptt.write_text(
        ptt.read_text(encoding="utf-8").replace("| PT-001 | [ ] |", "| PT-001 | [~] |"),
        encoding="utf-8",
    )
    return d


# --- violin_target ---------------------------------------------------------


def test_target_role_url(eng):
    r = _run("target", "--eng-dir", str(eng), "--role", "web", "--field", "url")
    assert r.returncode == 0, r.stderr
    assert r.stdout.strip() == "http://10.10.10.10"


def test_target_host_ip(eng):
    r = _run("target", "--eng-dir", str(eng), "--host", "10.10.10.10", "--field", "ip")
    assert r.returncode == 0, r.stderr
    assert r.stdout.strip() == "10.10.10.10"


def test_target_out_of_scope_rejected(eng):
    r = _run("target", "--eng-dir", str(eng), "--host", "10.99.99.99")
    assert r.returncode == 1
    assert "not in scope" in r.stdout


def test_target_requires_eng_dir():
    r = _run("target", "--host", "10.10.10.10")
    assert r.returncode == 1
    assert "--eng-dir is required" in r.stdout


# --- violin_exec_burst -----------------------------------------------------


def test_exec_burst_clean_review_or_approved(eng):
    """A batch of in-scope recon commands passes the gate (APPROVED or REVIEW
    on soft warnings) and arms the single sync lock rather than blocking."""
    from guard import sync as sync_state

    cmds = eng / "cmds.txt"
    cmds.write_text("nmap -sV 10.10.10.10\ngobuster dir -u http://10.10.10.10\n", encoding="utf-8")
    r = _run(
        "exec-burst",
        "--eng-dir",
        str(eng),
        "--phase",
        "recon",
        "--scope",
        str(eng / "scope" / "scope.yaml"),
        "--commands-file",
        str(cmds),
        "--session-id",
        "ts",
        "--skill-loaded-file",
        str(eng / "state" / ".skill-loaded-ts"),
        "--label",
        "recon-batch",
    )
    assert r.returncode in (0, 2), r.stdout
    assert "BURST VERDICT: DENIED" not in r.stdout, r.stdout
    # Only the LAST command arms the gate -> exactly one pending-sync lock.
    assert sync_state.has_pending_sync(str(eng)) is not None


def test_exec_burst_fail_closed_on_blocked_command(eng):
    """A batch containing a hard-blocked command (e.g. `rm -rf /`) is denied
    and the batch is halted at the first BLOCK (fail-closed)."""
    cmds = eng / "cmds2.txt"
    cmds.write_text("nmap -sV 10.10.10.10\nrm -rf /\n", encoding="utf-8")
    r = _run(
        "exec-burst",
        "--eng-dir",
        str(eng),
        "--phase",
        "recon",
        "--scope",
        str(eng / "scope" / "scope.yaml"),
        "--commands-file",
        str(cmds),
        "--session-id",
        "ts",
        "--skill-loaded-file",
        str(eng / "state" / ".skill-loaded-ts"),
        "--label",
        "bad-batch",
    )
    assert r.returncode == 1
    assert "BURST VERDICT: DENIED" in r.stdout, r.stdout
    assert "[1] rm -rf /" in r.stdout
    assert "destructive filesystem deletion is blocked" in r.stdout


def test_exec_burst_missing_commands_file(eng):
    r = _run(
        "exec-burst",
        "--eng-dir",
        str(eng),
        "--phase",
        "recon",
        "--scope",
        str(eng / "scope" / "scope.yaml"),
        "--commands-file",
        str(eng / "does-not-exist.txt"),
    )
    assert r.returncode == 1
    assert "commands file not found" in r.stdout


def test_plugin_exec_burst_accepts_inline_commands(monkeypatch, tmp_path):
    import importlib.util
    from subprocess import CompletedProcess

    plug = ROOT / "plugins" / "violin_guard"
    pkg = importlib.util.spec_from_file_location("vgpkg", plug / "__init__.py")
    mod = importlib.util.module_from_spec(pkg)
    mod.__path__ = [str(plug)]
    mod.__package__ = "vgpkg"
    sys.modules["vgpkg"] = mod
    pkg.loader.exec_module(mod)

    monkeypatch.setattr(
        mod.tools,
        "_authorize",
        lambda args: CompletedProcess(args=[], returncode=0, stdout="OK: allowed\n", stderr=""),
    )
    monkeypatch.setattr(
        mod.tools.executor,
        "execute",
        lambda command, **kwargs: {
            "status": "completed",
            "exit_code": 0,
            "executed": True,
            "sync_required": False,
            "sync_credit_remaining": 4,
            "command": command,
        },
    )
    raw = mod.tools.handle_exec_burst(
        {
            "eng_dir": str(tmp_path),
            "scope": str(tmp_path / "scope.yaml"),
            "phase": "recon",
            "commands": [
                "gobuster dir -u http://10.10.10.10 -H 'Host: nimbus.htb' -w /usr/share/wordlists/dirb/common.txt",
                "curl -H 'Host: nimbus.htb' http://10.10.10.10/",
            ],
            "session_id": "ts",
            "skill_loaded_file": str(tmp_path / "state" / ".skill-loaded-ts"),
            "label": "recon-batch",
        }
    )
    data = json.loads(raw)
    assert data["status"] == "approved"
    assert data["executed"] is True
    assert len(data["results"]) == 2
    assert "gobuster dir" in data["results"][0]["command"]
    assert "curl -H" in data["results"][1]["command"]


# --- plugin surface --------------------------------------------------------


def test_plugin_exposes_new_tools():
    import importlib.util

    import yaml

    plug = ROOT / "plugins" / "violin_guard"
    pkg = importlib.util.spec_from_file_location("vgpkg", plug / "__init__.py")
    mod = importlib.util.module_from_spec(pkg)
    mod.__path__ = [str(plug)]
    mod.__package__ = "vgpkg"
    sys.modules["vgpkg"] = mod
    pkg.loader.exec_module(mod)
    names = {t[0] for t in mod._TOOLS}
    assert "violin_exec_burst" in names
    assert "violin_target" in names

    manifest = yaml.safe_load((plug / "plugin.yaml").read_text(encoding="utf-8"))
    assert names == set(manifest["provides_tools"])
