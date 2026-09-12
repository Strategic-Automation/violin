"""Integration tests for operational probes, advisory hints, and closeout generation.

Tests:
1. Recency hints suppressed during burst and active batch.
2. Advisory hints do not deny handle_exec even with HERMES_YOLO_MODE unset.
3. Operational checks under PT-103/PT-104 in EXPLOITATION do not require hypotheses.
4. generate-closeout.py works via CLI and venv discovery.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from plugins.violin_guard import handlers as TOOLS
from plugins.violin_guard.core import bootstrap
from plugins.violin_guard.gates import command
from tests.guard.receipt_fixture import bind_active_task

ROOT = Path(__file__).resolve().parents[3]


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


def _init_test_engagement(tmp_path: Path) -> Path:
    eng = tmp_path / "eng"
    bootstrap.init_engagement(str(eng))

    # Set fully authorized scope
    scope_file = eng / "scope" / "scope.yaml"
    scope_file.write_text(_PLATFORM_SCOPE, encoding="utf-8")

    # Mark PT-101 [x], PT-103 [~]
    ptt_file = eng / "state" / "ptt.md"
    ptt_file.write_text(
        """# Pentesting Task Tree (PTT)

## Phase: RECON

| ID | Status | Task | Notes |
|---|---|---|---|
| PT-101 | [x] | Recon | done |

## Phase: EXPLOITATION

| ID | Status | Task | Notes |
|---|---|---|---|
| PT-103 | [~] | Exploitation & Operational Validation | active |
""",
        encoding="utf-8",
    )

    bind_active_task(eng, session_id="test-session-p1")

    return eng


def test_handle_exec_allows_pure_hints_without_yolo(monkeypatch, tmp_path):
    """Pure advisory hints must not cause handle_exec to deny execution in normal mode."""
    monkeypatch.delenv("HERMES_YOLO_MODE", raising=False)
    eng = _init_test_engagement(tmp_path)

    # Add a hypothesis that is older than 15 mins
    (eng / "hypotheses.md").write_text(
        """# Hypotheses
### H-001: Test target validation
- **Target:** 10.10.10.10
- **Status:** Candidate
- **Phase:** EXPLOITATION
- **Updated:** 2026-08-01 10:00 UTC
""",
        encoding="utf-8",
    )

    # Put a receipt in evidence/executions dated now
    exec_dir = eng / "evidence" / "executions"
    exec_dir.mkdir(parents=True, exist_ok=True)
    receipt = exec_dir / "2026-08-10T120000-exec.json"
    receipt.write_text('{"command": "test"}', encoding="utf-8")

    # Mock execution.execute to avoid network timeout against 10.10.10.10
    monkeypatch.setattr(
        "plugins.violin_guard.engine.execution.execute",
        lambda *args, **kwargs: {
            "executed": True,
            "exit_code": 0,
            "stdout_preview": "HTTP/1.1 200 OK",
            "stderr_preview": "",
            "command": kwargs.get("command", ""),
            "execution_id": "test-exec-1",
        },
    )

    # Command against 10.10.10.10 without curl -i will produce hints/warnings
    args = {
        "eng_dir": str(eng),
        "phase": "exploitation",
        "command": "curl -sS -i http://10.10.10.10:8080/test",
        "target": "10.10.10.10",
        "session_id": "test-session-p1",
    }

    # Execute should succeed (status == "ok") rather than status == "denied"
    out = json.loads(TOOLS.handle_exec(args))
    assert out["status"] == "ok", f"Expected ok, got {out}"


def test_exploitation_operational_probes_without_hypothesis(monkeypatch, tmp_path):
    """Under PT-103/PT-104 in EXPLOITATION, operational checks (CORS, rate-limiting) do not require hypotheses."""
    monkeypatch.delenv("HERMES_YOLO_MODE", raising=False)
    eng = _init_test_engagement(tmp_path)

    # Empty hypothesis board
    (eng / "hypotheses.md").write_text("# Hypotheses\n", encoding="utf-8")

    # Execute an operational curl check under PT-103
    args = {
        "eng_dir": str(eng),
        "phase": "exploitation",
        "command": "curl -sS -i http://10.10.10.10:8080/cors-check",
        "target": "10.10.10.10",
        "session_id": "test-session-p1",
    }

    res = command.check_command(
        command.CheckCommandArgs(
            command=args["command"],
            phase=args["phase"],
            eng_dir=args["eng_dir"],
            target=args["target"],
            session_id=args["session_id"],
        )
    )
    # Check that it did NOT produce hypothesis-missing error
    assert not any("requires at least one hypothesis" in err for err in res.errors)
    assert not any("no active hypothesis matches" in err for err in res.errors)


def test_generate_closeout_standalone_script_execution(tmp_path):
    """generate-closeout.py executes cleanly on an engagement."""
    eng = _init_test_engagement(tmp_path)

    # Create dummy finding in findings.jsonl
    findings_file = eng / "evidence" / "findings.jsonl"
    findings_file.parent.mkdir(parents=True, exist_ok=True)
    findings_file.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "finding_id": "FIND-001",
                "title": "Missing Security Headers",
                "severity": "Low",
                "summary": "Security headers are missing from HTTP responses.",
                "status": "validated",
                "receipt_paths": ["evidence/executions/headers.json"],
                "execution_ids": ["exec-1"],
                "evidence_paths": ["evidence/executions/headers.stdout.txt"],
            }
        )
        + "\n",
        encoding="utf-8",
    )

    closeout_script = ROOT / "scripts" / "generate-closeout.py"
    assert closeout_script.is_file()

    result = subprocess.run(
        [
            sys.executable,
            str(closeout_script),
            "--eng-dir",
            str(eng),
            "--target",
            "10.10.10.10",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, f"Script failed: {result.stderr}\nStdout: {result.stdout}"
    assert "OK: wrote" in result.stdout
    assert (eng / "evidence" / "reporting" / "findings.yaml").is_file()
    assert (eng / "reporting" / "report.md").is_file()
