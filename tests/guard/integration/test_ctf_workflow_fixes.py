import json

import pytest

from plugins.violin_guard import adapters, ptt, state
from plugins.violin_guard import handlers as service
from plugins.violin_guard.skill_receipts import SkillViewResult
from tests.guard.receipt_fixture import bind_active_task

_SCOPE_YAML = """targets:
  ip_addresses: ["10.129.2.5"]
  in_scope_urls: ["http://10.129.2.5"]
exclusions: {}
assessment_hosts:
  callback_hosts: ["10.10.14.233"]
authorized_parties: ["test owner"]
authorisation:
  confirmed: true
rules_of_engagement:
  allowed_actions: [recon, vuln-research, exploitation]
  forbidden_actions: []
engagement:
  name: ctf-test
  date: "2026-07-24"
  type: ctf
  client: test
"""


@pytest.fixture
def ctf_eng(tmp_path):
    eng = tmp_path / "eng"
    eng.mkdir()
    state_dir = eng / "state"
    state_dir.mkdir()
    scope_dir = eng / "scope"
    scope_dir.mkdir()
    evidence_dir = eng / "evidence" / "executions"
    evidence_dir.mkdir(parents=True)

    (scope_dir / "scope.yaml").write_text(_SCOPE_YAML, encoding="utf-8")
    (state_dir / "history.md").write_text("# History\n", encoding="utf-8")
    (state_dir / "hypotheses.md").write_text("# Hypotheses\n", encoding="utf-8")

    ptt_content = """# Pentesting Task Tree

## Phase: RECON
| PT-001 | [~] | Recon target service | initial note |

## Phase: EXPLOITATION
| PT-002 | [ ] | Exploit Cobbler CVE-2024-47533 | initial note |
"""
    (state_dir / "ptt.md").write_text(ptt_content, encoding="utf-8")

    bootstrap_data = {
        "schema_version": 2,
        "eng_dir": str(eng),
        "target": "10.129.2.5",
        "phase": "RECON",
        "initialized_at": "2026-07-24T00:00:00Z",
    }
    (state_dir / "bootstrap.json").write_text(json.dumps(bootstrap_data), encoding="utf-8")
    return eng


def test_listener_with_vpn_ip_allowed(ctf_eng, monkeypatch):
    """Verify violin_listener with attacker VPN IP is not blocked as out-of-scope target."""
    monkeypatch.setattr(adapters, "_installed_netcat_variant", lambda binary: ("nc", "openbsd"))

    def fake_exec(args, **kwargs):
        return json.dumps({"status": "ok", "executed": True, "command": args.get("command")})

    monkeypatch.setattr(service, "handle_exec", fake_exec)

    res_str = service.handle_listener(
        {
            "eng_dir": str(ctf_eng),
            "bind_host": "10.10.14.233",
            "port": 4444,
            "phase": "EXPLOITATION",
        }
    )
    res = json.loads(res_str)
    assert res.get("status") == "ok", res
    assert "10.10.14.233" in res.get("command", "")


def test_semantic_lock_requires_research_plus_meaningful_pivot(ctf_eng):
    state.record_semantic_review(
        ctf_eng,
        task_id="PT-001",
        hypothesis_id="H-001",
        skill="recon",
        technique="port-scan",
        outcome="no_progress",
        evidence_paths=[],
        next_action="none",
        next_technique="port-scan",
    )
    # Manually inject a lock into semantic-progress.json to simulate stuck state
    semantic_file = ctf_eng / "state" / "semantic-progress.json"
    data = state.read_json(semantic_file)
    data["lock"] = {"reason": "stuck test"}
    state.atomic_json(semantic_file, data)

    assert state.read_json(semantic_file).get("lock") is not None

    # A hypothesis edit alone is not evidence of progress and must retain the lock.
    service.handle_record_hypothesis(
        {
            "eng_dir": str(ctf_eng),
            "id": "H-001",
            "title": "Cobbler CVE-2024-47533 Vulnerability",
            "vuln_class": "command-injection",
            "status": "Candidate",
        }
    )

    assert state.read_json(semantic_file).get("lock") is not None

    state.record_research_attempt(ctf_eng, "web_search", True)
    state.record_semantic_review(
        ctf_eng,
        task_id="PT-001",
        hypothesis_id="H-001",
        skill="recon",
        technique="port-scan",
        outcome="no_progress",
        evidence_paths=[],
        next_action="test HTTP behavior",
        next_technique="http-enumeration",
    )
    assert state.read_json(semantic_file).get("lock") is None


def test_batch_review_with_running_background_tunnel(ctf_eng):
    """Verify reviewing a batch with a still-running background command succeeds."""
    bind_active_task(ctf_eng)
    state.mark_pending_sync(
        ctf_eng, "ssh -f -N -L 8080:127.0.0.1:80 user@10.129.2.5", "RECON", "PT-001"
    )

    # Create background execution receipt
    exec_id = "11111111-2222-3333-4444-555555555555"
    exec_record = {
        "execution_id": exec_id,
        "command": "ssh -f -N -L 8080:127.0.0.1:80 user@10.129.2.5",
        "phase": "RECON",
        "background": True,
        "status": "running",
        "pid": 99999,
        "evidence_paths": {
            "manifest": f"evidence/executions/{exec_id}.json",
            "stdout": f"evidence/executions/{exec_id}.stdout",
            "stderr": f"evidence/executions/{exec_id}.stderr",
        },
    }
    exec_dir = ctf_eng / "evidence" / "executions"
    exec_dir.mkdir(parents=True, exist_ok=True)
    state.atomic_json(exec_dir / f"{exec_id}.json", exec_record)
    (exec_dir / f"{exec_id}.stdout").write_text("", encoding="utf-8")
    (exec_dir / f"{exec_id}.stderr").write_text("", encoding="utf-8")

    res_str = service.handle_review_batch(
        {
            "eng_dir": str(ctf_eng),
            "id": "PT-001",
            "outcome": "progress",
            "status": "[~]",
            "note": "Tunnel running in background",
        }
    )
    res = json.loads(res_str)
    assert res.get("status") == "ok", res
    assert res.get("released") is True


def test_stale_active_ptt_task_auto_superseded(ctf_eng, monkeypatch):
    """Verify starting a new task when no pending batch exists auto-supersedes the prior task."""
    monkeypatch.setattr(
        service.HermesSkillViewAdapter,
        "view",
        lambda self, skill, **kwargs: SkillViewResult(True, content="test content"),
    )
    bind_active_task(ctf_eng)
    tasks = ptt.parse_ptt(ctf_eng / "state" / "ptt.md")
    active = ptt.find_active_task(tasks)
    assert active.id == "PT-001"

    # Start PT-002 without pending sync (step 1: prepare skill delivery)
    res_str1 = service.handle_record_ptt(
        {
            "eng_dir": str(ctf_eng),
            "id": "PT-002",
            "status": "[~]",
            "skill": "pentest",
            "technique": "cobbler-rce",
            "hypothesis_id": "H-001",
            "note": "Starting exploitation task",
        }
    )
    res1 = json.loads(res_str1)
    assert res1.get("status") == "skill_prepared", res1

    # Step 2: confirm binding and apply PTT transition
    res_str2 = service.handle_record_ptt(
        {
            "eng_dir": str(ctf_eng),
            "id": "PT-002",
            "status": "[~]",
            "skill": "pentest",
            "technique": "cobbler-rce",
            "hypothesis_id": "H-001",
            "note": "Starting exploitation task",
        }
    )
    res2 = json.loads(res_str2)
    assert res2.get("status") == "ok", res2

    updated_tasks = ptt.parse_ptt(ctf_eng / "state" / "ptt.md")
    new_active = ptt.find_active_task(updated_tasks)
    assert new_active.id == "PT-002"

    old_task = next(t for t in updated_tasks if t.id == "PT-001")
    assert old_task.status == "[x]"
    assert "superseded-by:PT-002" in old_task.note


def test_listener_with_ipv6_bind_host_allowed(ctf_eng, monkeypatch):
    """Verify violin_listener with IPv6 loopback bind_host (::1 or [::1]:4444) is allowed."""
    monkeypatch.setattr(adapters, "_installed_netcat_variant", lambda binary: ("nc", "openbsd"))

    def fake_exec(args, **kwargs):
        return json.dumps({"status": "ok", "executed": True, "command": args.get("command")})

    monkeypatch.setattr(service, "handle_exec", fake_exec)

    res_str = service.handle_listener(
        {
            "eng_dir": str(ctf_eng),
            "bind_host": "::1",
            "port": 4444,
            "phase": "EXPLOITATION",
        }
    )
    res = json.loads(res_str)
    assert res.get("status") == "ok", res

    res_str_bracket = service.handle_listener(
        {
            "eng_dir": str(ctf_eng),
            "bind_host": "[::1]:4444",
            "port": 4444,
            "phase": "EXPLOITATION",
        }
    )
    res_bracket = json.loads(res_str_bracket)
    assert res_bracket.get("status") == "ok", res_bracket


def test_invalid_ptt_start_status_error_message(ctf_eng):
    """Verify starting a task with status [x] gives an accurate error message."""
    ptt_path = ctf_eng / "state" / "ptt.md"
    ptt.update_task(ptt_path, "PT-002", "[x]", "closed task")
    updated_tasks = ptt.parse_ptt(ptt_path)

    from plugins.violin_guard.handlers.ptt_handlers import _start_ptt_task

    with pytest.raises(ValueError, match=r"must be \[\ \] or \[\~\] before it can be started"):
        _start_ptt_task(
            ptt_path, updated_tasks, "PT-002", "[~]", "Attempt restart", eng_dir=ctf_eng
        )


def test_parse_target_token_ipv6_url():
    """Verify targets._parse_target_token correctly extracts IPv6 address from URL."""
    from plugins.violin_guard import targets

    res = targets._parse_target_token("http://[2001:db8::1]:8080/api")
    assert res == "2001:db8::1"


def test_update_hypothesis_merge_existing_fields(ctf_eng):
    """Verify update_hypothesis preserves existing runtime_evidence during partial field update."""
    from plugins.violin_guard import hypotheses

    h_file = ctf_eng / "hypotheses.md"
    evidence = ctf_eng / "evidence" / "executions" / "1.json"
    evidence.parent.mkdir(parents=True, exist_ok=True)
    evidence.write_text('{"status":"completed"}', encoding="utf-8")
    h1 = hypotheses.update_hypothesis(
        h_file,
        id="H-001",
        title="Original Title",
        status="Validated",
        runtime_evidence="evidence/executions/1.json",
        in_scope_hosts={"10.129.2.5"},
        target="10.129.2.5",
    )
    assert h1.status == "Validated"

    # Update only the title; should not wipe out runtime_evidence or fail validation
    h2 = hypotheses.update_hypothesis(
        h_file,
        id="H-001",
        title="Updated Title",
        in_scope_hosts={"10.129.2.5"},
    )
    assert h2.title == "Updated Title"
    assert h2.runtime_evidence == "evidence/executions/1.json"
    assert h2.status == "Validated"


def test_findings_lowercase_hypothesis_id(ctf_eng):
    """Verify _validate_from_pending_batch accepts lowercase 'h-001' hypothesis_id."""
    from plugins.violin_guard import findings, hypotheses

    h_file = ctf_eng / "hypotheses.md"
    evidence = ctf_eng / "evidence" / "executions" / "1.json"
    evidence.parent.mkdir(parents=True, exist_ok=True)
    evidence.write_text('{"status":"completed"}', encoding="utf-8")
    hypotheses.update_hypothesis(
        h_file,
        id="H-001",
        title="SQLi",
        status="Validated",
        runtime_evidence="evidence/executions/1.json",
        in_scope_hosts={"10.129.2.5"},
        target="10.129.2.5",
    )

    pending = {
        "batch_id": "b1",
        "commands": [{"command": "echo test"}],
        "ptt_task_id": "PT-001",
        "phase": "RECON",
    }

    # Write a dummy execution receipt matched by pending command
    exec_dir = ctf_eng / "evidence" / "executions"
    exec_record = {
        "command": "echo test",
        "evidence_paths": {"manifest": "evidence/executions/e1.json"},
    }
    (exec_dir / "e1.json").write_text(json.dumps(exec_record), encoding="utf-8")

    draft = findings._validate_from_pending_batch(
        ctf_eng,
        pending,
        title="SQLi Finding",
        severity="High",
        description="Desc",
        impact="Impact",
        remediation="Remediation",
        finding_id="FIND-001",
        hypothesis_id="h-001",
    )
    assert draft["hypothesis_id"] == "H-001"


def test_terminal_policy_ipv6_target_blocked():
    """Verify raw terminal guard blocks IPv6 host literals."""
    from plugins.violin_guard import terminal_policy

    msg = terminal_policy.block_terminal_command("nc 2001:db8::1 80")
    assert msg is not None
    assert "RAW TERMINAL TARGET EXECUTION BLOCKED" in msg
