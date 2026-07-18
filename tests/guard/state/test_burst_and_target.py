"""Regression tests for burst mode (violin_exec_burst) and violin_target.

These exercise the real CLI end-to-end (subprocess) so the argparse wiring,
dispatch, and scope-host resolution are covered, not just the in-process funcs.
"""

import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "scripts"))

from plugins.violin_guard import (  # noqa: E402
    bootstrap,
    execution,
    ptt,  # noqa: E402
    service,  # noqa: E402
    state,
)
from plugins.violin_guard import service as tools  # noqa: E402
from plugins.violin_guard.targets import resolve_target  # noqa: E402

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


def test_relative_engagement_paths_stay_under_profile_root(monkeypatch):
    monkeypatch.delenv("VIOLIN_ENG_ROOT", raising=False)

    assert state.resolve_eng_dir("engagements/demo") == (ROOT / "engagements" / "demo").resolve()


def test_public_handlers_serialize_expected_errors(tmp_path):
    cases = (
        (service.handle_status, {}),
        (
            service.handle_exec_status,
            {"eng_dir": str(tmp_path), "execution_id": "not-an-execution-id"},
        ),
        (service.handle_search_exploit, {}),
    )

    for handler, args in cases:
        result = json.loads(handler(args))
        assert result["status"] == "error"
        assert result["error"]


def test_target_role_preserves_ipv6_url_hostname():
    scope = {"targets": {"roles": {"web": "http://[2001:db8::1]:8080"}}}

    assert resolve_target(scope, role="web", host_query=None, field="host") == "2001:db8::1"


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
    return d


# --- violin_target ---------------------------------------------------------


def test_target_role_url(eng):
    """handle_target returns the first in-scope IP (canonical IP form)."""
    r = _run("target", "--eng-dir", str(eng), "--role", "web", "--field", "url")
    assert r.returncode == 0, r.stderr
    assert r.stdout.strip() == "10.10.10.10"


def test_target_role_url_returns_first_in_scope_ip(eng):
    """handle_target resolves a role to its in-scope target by returning the
    first in-scope IP; it does not perform scope validation (the per-command
    check-command gate is what enforces scope)."""
    scope = (eng / "scope" / "scope.yaml").read_text(encoding="utf-8")
    scope = scope.replace("in_scope_urls: []", "in_scope_urls: [http://10.10.10.10]")
    (eng / "scope" / "scope.yaml").write_text(scope, encoding="utf-8")
    r = _run("target", "--eng-dir", str(eng), "--role", "web", "--field", "url")
    assert r.returncode == 0, r.stderr
    assert r.stdout.strip() == "10.10.10.10"


def test_target_host_ip(eng):
    r = _run("target", "--eng-dir", str(eng), "--host", "10.10.10.10", "--field", "ip")
    assert r.returncode == 0, r.stderr
    assert r.stdout.strip() == "10.10.10.10"


def test_target_out_of_scope_host_returns_in_scope_ip(eng):
    """handle_target resolves from scope.yaml (first in-scope IP) and does NOT
    perform scope validation itself â€” the per-command check-command gate is the
    enforcement point. So an out-of-scope --host still yields rc=0 with the
    in-scope IP, proving resolution is scope-file driven, not host-argument driven."""
    r = _run("target", "--eng-dir", str(eng), "--host", "10.99.99.99")
    assert r.returncode == 0, r.stderr
    assert r.stdout.strip() == "10.10.10.10"


def test_target_requires_eng_dir():
    r = _run("target", "--host", "10.10.10.10")
    assert r.returncode == 2  # argparse: required argument missing


# --- violin_exec_burst -----------------------------------------------------

_GATE_OK = {
    "status": "ok",
    "errors": [],
    "warnings": [],
    "infos": [],
}


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
        remaining = execution._commit_guard_state(
            Path(eng_dir), command, phase, active.id if active else ""
        )
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
        }

    monkeypatch.setattr(execution, "execute", fake_execute)
    return rec


def test_exec_burst_clean_review_or_approved(eng, monkeypatch):
    """A batch of in-scope recon commands passes the gate (batch_complete, no
    DENIED) and arms a single pending-sync lock."""
    rec = _patch_burst(monkeypatch, str(eng))
    data = json.loads(
        service.handle_exec_burst(
            {
                "eng_dir": str(eng),
                "scope": str(eng / "scope" / "scope.yaml"),
                "phase": "recon",
                "commands": [
                    "nmap -sV 10.10.10.10",
                    "gobuster dir -u http://10.10.10.10",
                ],
                "session_id": "ts",
                "skill_loaded_file": str(eng / "state" / ".skill-loaded-ts"),
                "label": "recon-batch",
            }
        )
    )
    assert data["status"] == "batch_complete", data
    assert data["executed"] == 2, data
    assert len(rec["commands"]) == 2
    # Only the LAST command arms the gate -> exactly one pending-sync lock.
    assert state.has_pending_sync(str(eng)) is not None


@pytest.mark.parametrize("secondary_only_host", ["listener.example", "github.com"])
def test_exec_burst_denies_secondary_only_primary_target(eng, monkeypatch, secondary_only_host):
    rec = _patch_burst(monkeypatch, str(eng))
    data = json.loads(
        service.handle_exec_burst(
            {
                "eng_dir": str(eng),
                "scope": str(eng / "scope" / "scope.yaml"),
                "phase": "recon",
                "commands": [f"curl https://{secondary_only_host}"],
                "target": secondary_only_host,
                "session_id": "ts",
                "skill_loaded_file": str(eng / "state" / ".skill-loaded-ts"),
                "label": "secondary-only-primary",
            }
        )
    )

    assert data["status"] == "denied"
    assert data["executed"] == 0
    assert "secondary-only endpoint" in data["reason"]
    assert rec["commands"] == []


def test_exec_burst_fail_closed_on_blocked_command(eng, monkeypatch):
    """A batch containing a hard-blocked command (e.g. `rm -rf /`) is denied
    and the batch is halted at the first BLOCK (fail-closed)."""
    rec = _patch_burst(monkeypatch, str(eng))
    data = json.loads(
        service.handle_exec_burst(
            {
                "eng_dir": str(eng),
                "scope": str(eng / "scope" / "scope.yaml"),
                "phase": "recon",
                "commands": [
                    "nmap -sV 10.10.10.10",
                    "rm -rf /",
                ],
                "session_id": "ts",
                "skill_loaded_file": str(eng / "state" / ".skill-loaded-ts"),
                "label": "bad-batch",
            }
        )
    )
    assert data["status"] == "denied", data
    assert (
        data["reason"] == "command [2] blocked: destructive filesystem deletion (rm -rf) is blocked"
    ), data
    # First command ran; the blocked one did not, and nothing after it ran.
    assert rec["commands"] == ["nmap -sV 10.10.10.10"]


def test_exec_burst_missing_commands_file(eng):
    data = json.loads(
        service.handle_exec_burst(
            {
                "eng_dir": str(eng),
                "scope": str(eng / "scope" / "scope.yaml"),
                "phase": "recon",
                "commands_file": str(eng / "does-not-exist.txt"),
                "session_id": "ts",
                "skill_loaded_file": str(eng / "state" / ".skill-loaded-ts"),
            }
        )
    )
    assert data["status"] == "error", data
    assert "commands file not found" in data["error"], data


def test_plugin_exec_burst_accepts_inline_commands(monkeypatch, tmp_path):
    """In-process handle_exec_burst with a monkeypatched executor runs every
    inline command and reports batch_complete without a real network call."""
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
    _patch_burst(monkeypatch, str(d))
    raw = service.handle_exec_burst(
        {
            "eng_dir": str(d),
            "scope": str(d / "scope" / "scope.yaml"),
            "phase": "recon",
            "commands": [
                "gobuster dir -u http://10.10.10.10 -H 'Host: nimbus.htb' -w /usr/share/wordlists/dirb/common.txt",
                "curl -H 'Host: nimbus.htb' http://10.10.10.10/",
            ],
            "session_id": "ts",
            "skill_loaded_file": str(d / "state" / ".skill-loaded-ts"),
            "label": "recon-batch",
        }
    )
    data = json.loads(raw)
    assert data["status"] == "batch_complete"
    assert data["executed"] == 2
    assert len(data["results"]) == 2
    assert "gobuster dir" in data["results"][0]["command"]
    assert "curl -H" in data["results"][1]["command"]


# --- plugin surface --------------------------------------------------------


def test_plugin_exposes_new_tools():
    import yaml

    names = (
        {t[0] for t in tools._TOOLS}
        if hasattr(tools, "_TOOLS")
        else set(n for n in dir(tools) if n.startswith("handle_"))
    )
    assert "handle_exec_burst" in names
    assert "handle_target" in names

    manifest = yaml.safe_load(
        (ROOT / "plugins" / "violin_guard" / "plugin.yaml").read_text(encoding="utf-8")
    )
    tool_names = set(manifest["provides_tools"])
    assert "violin_exec_burst" in tool_names
    assert "violin_target" in tool_names
    assert "violin_review_batch" in tool_names
    assert (
        not {
            "violin_sync_done",
            "violin_review_and_release",
            "violin_finding",
        }
        & tool_names
    )


def test_status_skill_section_reports_load_state_and_exit_code(eng):
    state.record_session_id(eng, "ts")
    loaded = _run("status", "--eng-dir", str(eng), "--section", "skill")
    loaded_data = json.loads(loaded.stdout)
    assert loaded.returncode == 0
    assert loaded_data["loaded"] is True

    marker = Path(loaded_data["marker"])
    marker.unlink()
    missing = _run("status", "--eng-dir", str(eng), "--section", "skill")
    missing_data = json.loads(missing.stdout)
    assert missing.returncode == 1
    assert missing_data["loaded"] is False


@pytest.mark.parametrize(
    "removed",
    [
        "review-and-release",
        "finding",
        "sync-done",
        "record-history",
        "message-tick",
        "skill-status",
        "check-skill-loaded",
    ],
)
def test_removed_cli_commands_are_absent(removed):
    result = _run(removed, "--help")
    assert result.returncode != 0
    assert "invalid choice" in result.stderr


def test_review_batch_cli_exposes_lifecycle_and_optional_finding_fields():
    result = _run("review-batch", "--help")
    assert result.returncode == 0
    assert "--status" in result.stdout
    assert "--note" in result.stdout
    assert "--finding-title" in result.stdout
