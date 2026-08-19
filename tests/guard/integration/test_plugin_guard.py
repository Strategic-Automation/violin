from __future__ import annotations

import json
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path

import pytest

from plugins.violin_guard.core.skill_receipts import SkillViewResult
from tests.guard.receipt_fixture import bind_active_task

ROOT = Path(__file__).resolve().parents[3]

# Make `violin_guard` resolvable
_PLUGIN_ROOT = ROOT / "plugins" / "violin_guard"
_PLUGIN_PARENT = _PLUGIN_ROOT.parent
if str(_PLUGIN_PARENT) not in sys.path:
    sys.path.insert(0, str(_PLUGIN_PARENT))

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


from plugins.violin_guard import handlers as TOOLS
from plugins.violin_guard.core import bootstrap, history, hypotheses, ptt, state
from plugins.violin_guard.core.targets import extract_target_candidates
from plugins.violin_guard.engine import execution
from plugins.violin_guard.gates import command
from plugins.violin_guard.handlers import ptt_handlers


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
        remaining = state.spend_sync_credit(str(engagement), phase)
        # Mirror real execution: tick command counter, mark pending sync, set heartbeat if interval reached
        from plugins.violin_guard.core.phases import normalize_phase, suppresses_heartbeat

        count = state.tick_command(str(engagement))
        active = ptt.find_active_task(ptt.parse_ptt(engagement / "state" / "ptt.md"))
        state.mark_pending_sync(str(engagement), command, phase, active.id if active else "")
        phase_enum = normalize_phase(phase)
        if count % state.COMMAND_INTERVAL == 0 and not suppresses_heartbeat(phase_enum):
            state.set_heartbeat_pending(
                str(engagement),
                f"Reached {count} executed target commands. Review engagement files for drift.",
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


def test_meta_loaded():
    # Current plugin surface: handle_* command entrypoints registered.
    for name in (
        "handle_exec",
        "handle_review_batch",
        "handle_record_ptt",
        "handle_record_hypothesis",
        "handle_exec_burst",
    ):
        assert hasattr(TOOLS, name), f"plugin must expose {name}"
    for removed in (
        "handle_sync_done",
        "handle_review_and_release",
        "handle_finding",
        "handle_check_command",
        "handle_ffuf",
        "handle_httpx",
        "handle_nuclei",
        "handle_listener",
        "handle_search_exploit",
    ):
        assert not hasattr(TOOLS, removed), f"plugin must not expose removed handler {removed}"


def test_recon_does_not_require_hypothesis(tmp_path):
    """Recon should not require a hypothesis yet; it is the discovery phase
    that creates the evidence hypotheses later consume."""
    skill_file = tmp_path / ".skill-loaded-ts"
    eng = _init_e2e(tmp_path, skill_file)

    result = command.check_command(
        command.CheckCommandArgs(
            command="nmap -sV 10.10.10.10",
            phase="recon",
            eng_dir=str(eng),
            scope=str(eng / "scope" / "scope.yaml"),
            session_id="ts",
        )
    )

    assert not result.errors
    assert not any("hypothesis guard:" in warning for warning in result.warnings)

    # Vuln-research with NO hypotheses should error
    research = command.check_command(
        command.CheckCommandArgs(
            command="nmap -sV 10.10.10.10",
            phase="vuln-research",
            eng_dir=str(eng),
            scope=str(eng / "scope" / "scope.yaml"),
            session_id="ts",
        )
    )
    assert any("requires at least one hypothesis" in error.lower() for error in research.errors)
    assert any("violin_record_hypothesis" in error for error in research.errors)

    # Add a fresh hypothesis - should pass without warnings
    ts = datetime.now(UTC).strftime("%Y-%m-%d %H:%M")
    (eng / "hypotheses.md").write_text(
        (eng / "hypotheses.md").read_text(encoding="utf-8")
        + (
            f"\n### H-001: SMB share exposed\n- **Status:** Candidate\n- **Phase:** VULN_RESEARCH\n"
            f"- **Target:** 10.10.10.10\n- **Updated:** {ts} UTC\n"
        ),
        encoding="utf-8",
    )
    ptt_path = eng / "state" / "ptt.md"
    ptt_path.write_text(
        ptt_path.read_text(encoding="utf-8")
        .replace("| PT-010 | [~] |", "| PT-010 | [x] |")
        .replace("| PT-030 | [ ] |", "| PT-030 | [~] |"),
        encoding="utf-8",
    )
    bind_active_task(eng, "ts")
    research2 = command.check_command(
        command.CheckCommandArgs(
            command="nmap -sV 10.10.10.10",
            phase="vuln-research",
            eng_dir=str(eng),
            scope=str(eng / "scope" / "scope.yaml"),
            session_id="ts",
        )
    )
    assert not research2.errors
    assert not any("hypothesis" in warning.lower() for warning in research2.warnings)

    osv_research = command.check_command(
        command.CheckCommandArgs(
            command="curl -s https://api.osv.dev/v1/query",
            phase="vuln-research",
            eng_dir=str(eng),
            target="api.osv.dev",
            session_id="ts",
        )
    )
    assert not osv_research.errors
    assert any("authorized research endpoint" in info for info in osv_research.infos)

    # Add a stale hypothesis - should warn
    old_ts = "2020-01-01 00:00"
    (eng / "hypotheses.md").write_text(
        (eng / "hypotheses.md").read_text(encoding="utf-8")
        + (
            f"\n### H-002: Old hypothesis\n- **Status:** Candidate\n- **Phase:** VULN_RESEARCH\n"
            f"- **Target:** 10.10.10.10\n- **Updated:** {old_ts} UTC\n"
        ),
        encoding="utf-8",
    )
    research3 = command.check_command(
        command.CheckCommandArgs(
            command="nmap -sV 10.10.10.10",
            phase="vuln-research",
            eng_dir=str(eng),
            scope=str(eng / "scope" / "scope.yaml"),
            session_id="ts",
        )
    )
    assert any("hypothesis guard:" in warning for warning in research3.warnings)


def test_exploit_phase_does_not_gate_on_research(tmp_path):
    """Online research is encouraged but never a hard gate on exploit execution.

    Neither named nor unnamed exploit commands may be blocked for missing
    CVE/Exploit Research rows — a per-hypothesis research requirement degrades
    into a bookkeeping tax that walls off the whole exploit phase.
    """
    skill_file = tmp_path / ".skill-loaded-ts"
    eng = _init_e2e(tmp_path, skill_file)
    ts = datetime.now(UTC).strftime("%Y-%m-%d %H:%M")
    (eng / "hypotheses.md").write_text(
        (eng / "hypotheses.md").read_text(encoding="utf-8")
        + (
            f"\n### H-001: JWT alg none\n- **Status:** Validated\n- **Phase:** EXPLOITATION\n"
            f"- **Target:** duck-store.escape.tech\n- **CVE Research:** NVD queried; no CVE\n"
            f"- **Exploit Research:** ExploitDB; none applicable\n- **Updated:** {ts} UTC\n"
            f"\n### H-002: No research done\n- **Status:** Candidate\n- **Phase:** EXPLOITATION\n"
            f"- **Target:** duck-store.escape.tech\n- **Updated:** {ts} UTC\n"
        ),
        encoding="utf-8",
    )
    ptt_path = eng / "state" / "ptt.md"
    ptt_path.write_text(
        ptt_path.read_text(encoding="utf-8")
        .replace("| PT-010 | [~] |", "| PT-010 | [x] |")
        .replace("| PT-030 | [ ] |", "| PT-030 | [~] |"),
        encoding="utf-8",
    )
    bind_active_task(eng, "ts")

    # Named hypothesis without research rows: must NOT be blocked.
    named = command.check_command(
        command.CheckCommandArgs(
            command="curl -sk -i https://duck-store.escape.tech/api/v1/admin",
            phase="exploitation",
            eng_dir=str(eng),
            scope=str(eng / "scope" / "scope.yaml"),
            hypothesis_id="H-002",
            session_id="ts",
        )
    )
    assert not any("online research" in error.lower() for error in named.errors)

    # Unnamed command: research must not be a gate either.
    unnamed = command.check_command(
        command.CheckCommandArgs(
            command="curl -sk -i https://duck-store.escape.tech/api/v1/admin",
            phase="exploitation",
            eng_dir=str(eng),
            scope=str(eng / "scope" / "scope.yaml"),
            session_id="ts",
        )
    )
    assert not any("online research" in error.lower() for error in unnamed.errors)


def test_target_scanner_ignores_dotted_files_and_handles_dev_tcp_endpoint():
    candidates = extract_target_candidates(
        "python3 server.py --output 01-nmap-full.txt "
        "bash -c 'sock.close(); s.close(); echo test > /dev/tcp/10.10.15.65/4445'"
    )

    assert "10.10.15.65" in candidates
    assert "10.10.15.65/44" not in candidates
    assert "server.py" not in candidates
    assert "01-nmap-full.txt" not in candidates
    assert "sock.close" not in candidates
    assert "s.close" not in candidates


def test_hypothesis_id_and_target_are_canonicalized_without_false_collisions(tmp_path):
    path = tmp_path / "hypotheses.md"
    path.write_text("# Hypothesis Board\n\n### H-H-001: malformed stale entry\n", encoding="utf-8")

    record = hypotheses.update_hypothesis(
        path,
        in_scope_hosts={"10.10.15.65"},
        id="H-001",
        title="Scoped endpoint test",
        status="Candidate",
        phase="EXPLOITATION",
        target="http://10.10.15.65:4445",
        cve_research="web_search scoped endpoint CVE; NVD; not applicable",
        exploit_research="web_search scoped endpoint exploit; GitHub; no results",
    )

    assert record.id == "001"
    text = path.read_text(encoding="utf-8")
    assert "### H-001: Scoped endpoint test" in text
    assert "H-H-001" not in text

    result = command.check_hypothesis_freshness(
        tmp_path,
        command.Phase.EXPLOITATION,
        "bash -c 'echo test > /dev/tcp/10.10.15.65/4445' > 01-nmap-full.txt",
    )
    assert not result.errors, result.errors


def test_hypothesis_refuses_syntax_uncertain_rejection(tmp_path):
    path = tmp_path / "hypotheses.md"
    with pytest.raises(ValueError, match="must remain active for re-test"):
        hypotheses.update_hypothesis(
            path,
            in_scope_hosts={"10.10.15.65"},
            id="001",
            title="PJL file download",
            status="Rejected",
            phase="EXPLOITATION",
            target="10.10.15.65",
            test_command='@PJL FSDOWNLOAD NAME="x" SIZE=1',
            test_response="FILEERROR=1",
            verification_status="syntax_uncertain",
            rejection_reason="argument order needs source-verified re-test",
        )
    assert not path.exists(), "invalid rejection must not mutate the board"


def test_hypothesis_preserves_verified_rejection_details(tmp_path):
    path = tmp_path / "hypotheses.md"
    record = hypotheses.update_hypothesis(
        path,
        in_scope_hosts={"10.10.15.65"},
        id="001",
        title="PJL file download",
        status="Rejected",
        phase="EXPLOITATION",
        target="10.10.15.65",
        test_command='@PJL FSDOWNLOAD NAME="x" SIZE=1',
        test_response="parser branch proves feature disabled",
        verification_status="not_implemented",
        rejection_reason="source-verified stub",
    )

    assert record.verification_status == "not_implemented"
    text = path.read_text(encoding="utf-8")
    assert '- **Test Command:** @PJL FSDOWNLOAD NAME="x" SIZE=1' in text
    assert "- **Verification Status:** not_implemented" in text
    assert "- **Rejection Reason:** source-verified stub" in text


def test_hypothesis_write_accepts_descriptive_target_context(tmp_path):
    record = hypotheses.update_hypothesis(
        tmp_path / "hypotheses.md",
        in_scope_hosts={"cctv.htb"},
        id="001",
        title="Camera portal",
        status="Candidate",
        phase="VULN_RESEARCH",
        target="cctv.htb (/zm/index.php, camera portal)",
    )
    assert record.target == "cctv.htb (/zm/index.php, camera portal)"


def test_exploitation_hypothesis_match_accepts_manual_field_order(tmp_path):
    (tmp_path / "hypotheses.md").write_text(
        """### H-001: Queue service validation
- **Target:** 10.129.47.140:1515
- **Port:** 1515
- **Evidence:** evidence/vuln-research/queue.txt
- **CVE Research:** web_search queue service 1515 CVE; NVD; no results
- **Exploit Research:** web_search queue service 1515 exploit; GitHub; no results
- **Status:** Validated
- **Phase:** EXPLOITATION
""",
        encoding="utf-8",
    )

    result = command.check_hypothesis_freshness(
        tmp_path, command.Phase.EXPLOITATION, "python3 exploit.py 10.129.47.140 1515"
    )
    assert not result.errors, result.errors


def test_exploitation_hints_when_research_missing_but_does_not_block(tmp_path):
    (tmp_path / "hypotheses.md").write_text(
        """### H-001: Queue service validation
- **Target:** 10.129.47.140:1515
- **Status:** Likely
- **Phase:** VULN_RESEARCH
- **CVE Research:** web_search queue service 1515 CVE; NVD; no results
""",
        encoding="utf-8",
    )

    result = command.check_hypothesis_freshness(
        tmp_path, command.Phase.EXPLOITATION, "python3 exploit.py 10.129.47.140 1515"
    )
    # Missing Exploit Research yields a hint, never a block.
    assert not result.errors, result.errors
    assert any("hint:" in w.lower() and "exploit research" in w.lower() for w in result.warnings)

    (tmp_path / "hypotheses.md").write_text(
        (tmp_path / "hypotheses.md").read_text(encoding="utf-8")
        + "- **Exploit Research:** web_search queue service 1515 PoC; GitHub; source unavailable\n",
        encoding="utf-8",
    )
    allowed = command.check_hypothesis_freshness(
        tmp_path, command.Phase.EXPLOITATION, "python3 exploit.py 10.129.47.140 1515"
    )
    assert not any(
        "hint:" in w.lower() and "exploit research" in w.lower() for w in allowed.warnings
    )


def test_hypothesis_enforces_scope_target_fallback(tmp_path):
    """Verify hypothesis guard checks scope target when command contains no target string."""
    (tmp_path / "scope").mkdir(parents=True, exist_ok=True)
    (tmp_path / "scope" / "scope.yaml").write_text(
        "targets:\n  ip_addresses:\n    - 10.129.47.140\n"
        "rules_of_engagement:\n  allowed_actions: [RECON, EXPLOITATION]\n"
        "engagement:\n  name: Test\n"
        "authorized_parties: [Tester]\n"
        "authorisation:\n  confirmed: true\n",
        encoding="utf-8",
    )
    # Hypothesis is for a DIFFERENT target host (192.168.1.1)
    (tmp_path / "hypotheses.md").write_text(
        "### H-001: Other host\n"
        "- **Target:** 192.168.1.1\n"
        "- **Status:** Validated\n"
        "- **Phase:** EXPLOITATION\n"
        "- **CVE Research:** Done\n"
        "- **Exploit Research:** Done\n",
        encoding="utf-8",
    )

    # Command has no IP string, but scope target 10.129.47.140 should NOT match 192.168.1.1 hypothesis
    result = command.check_hypothesis_freshness(
        tmp_path, command.Phase.EXPLOITATION, "python3 exploit.py"
    )
    assert result.errors, "Expected error when hypothesis target doesn't match scope target"
    assert any(
        "requires a non-rejected hypothesis matching the command target" in err
        for err in result.errors
    )


def test_rejected_hypothesis_testable_when_explicitly_linked(tmp_path):
    """A Rejected hypothesis must remain testable when the agent explicitly
    links its hypothesis_id, so the cheapest-test that the VULN_RESEARCH
    close gate requires can actually run (reject-then-test deadlock fix)."""
    (tmp_path / "scope").mkdir(parents=True, exist_ok=True)
    (tmp_path / "scope" / "scope.yaml").write_text(
        "targets:\n  in_scope_urls: [https://duck-store.escape.tech]\n"
        "  ip_addresses: []\n"
        "rules_of_engagement:\n  allowed_actions: [RECON, VULN_RESEARCH]\n"
        "engagement:\n  name: Test\n"
        "authorized_parties: [Tester]\n"
        "authorisation:\n  confirmed: true\n",
        encoding="utf-8",
    )
    (tmp_path / "hypotheses.md").write_text(
        "### H-001: Default creds login\n"
        "- **Target:** https://duck-store.escape.tech\n"
        "- **Status:** Rejected\n"
        "- **Phase:** VULN_RESEARCH\n",
        encoding="utf-8",
    )

    # Explicitly linked to H-001: the Rejected hypothesis must be eligible so
    # its cheapest test can run.
    result = command.check_hypothesis_freshness(
        tmp_path,
        command.Phase.VULN_RESEARCH,
        "curl -i https://duck-store.escape.tech/api/v1/auth/login",
        hypothesis_id="H-001",
    )
    assert not result.errors, f"Rejected-but-linked hypothesis should be testable: {result.errors}"


def test_unphased_hypothesis_defaults_to_current_phase_when_linked(tmp_path):
    """An unphased hypothesis explicitly linked during VULN_RESEARCH defaults
    to the current phase so it can be dispositioned (empty-phase deadlock fix)."""
    (tmp_path / "scope").mkdir(parents=True, exist_ok=True)
    (tmp_path / "scope" / "scope.yaml").write_text(
        "targets:\n  in_scope_urls: [https://duck-store.escape.tech]\n"
        "rules_of_engagement:\n  allowed_actions: [RECON, VULN_RESEARCH]\n"
        "engagement:\n  name: Test\n"
        "authorized_parties: [Tester]\n"
        "authorisation:\n  confirmed: true\n",
        encoding="utf-8",
    )
    (tmp_path / "hypotheses.md").write_text(
        "### H-001: API surface\n"
        "- **Target:** https://duck-store.escape.tech\n"
        "- **Status:** Candidate\n"
        "- **Phase:**\n",  # empty phase
        encoding="utf-8",
    )

    result = command.check_hypothesis_freshness(
        tmp_path,
        command.Phase.VULN_RESEARCH,
        "curl -i https://duck-store.escape.tech/api/v1/products",
        hypothesis_id="H-001",
    )
    assert not result.errors, (
        f"Unphased-but-linked hypothesis should default to current phase: {result.errors}"
    )


def test_check_command_routes_research_hint_to_active_task_hypothesis(tmp_path):
    """Verify check_command binds the active PTT task's hypothesis and hints, not blocks.

    The active task note links H-002; the research hint must mention H-002
    (not the researched H-001) and must never be a hard error.
    """
    (tmp_path / "scope").mkdir(parents=True, exist_ok=True)
    (tmp_path / "scope" / "scope.yaml").write_text(
        "targets:\n  ip_addresses:\n    - 10.129.47.140\n"
        "rules_of_engagement:\n  allowed_actions: [RECON, EXPLOITATION]\n"
        "engagement:\n  name: Test\n"
        "authorized_parties: [Tester]\n"
        "authorisation:\n  confirmed: true\n",
        encoding="utf-8",
    )
    (tmp_path / "state").mkdir(parents=True, exist_ok=True)
    (tmp_path / "state" / "ptt.md").write_text(
        "## Phase: EXPLOITATION\n\n| PT-001 | [~] | Exploit Task | testing H-002 |\n",
        encoding="utf-8",
    )
    # H-001 has research; active task links H-002 which has NO research.
    (tmp_path / "hypotheses.md").write_text(
        "### H-001: First\n"
        "- **Target:** 10.129.47.140\n"
        "- **Status:** Validated\n"
        "- **Phase:** EXPLOITATION\n"
        "- **CVE Research:** Done\n"
        "- **Exploit Research:** Done\n\n"
        "### H-002: Linked Task Hypothesis\n"
        "- **Target:** 10.129.47.140\n"
        "- **Status:** Candidate\n"
        "- **Phase:** EXPLOITATION\n"
        "- **CVE Research:** \n"
        "- **Exploit Research:** \n",
        encoding="utf-8",
    )

    cmd_args = command.CheckCommandArgs(
        command="python3 exploit.py 10.129.47.140",
        phase="EXPLOITATION",
        eng_dir=str(tmp_path),
        scope=str(tmp_path / "scope" / "scope.yaml"),
        session_id="test-session",
    )
    res = command.check_command(cmd_args)
    # Research must not block, but the hint must name the bound hypothesis.
    assert not any("missing CVE Research" in err for err in res.errors)
    assert any("hint:" in w.lower() and "H-002" in w for w in res.warnings)


class _ReadySkillAdapter:
    def view(self, *_args, **_kwargs) -> SkillViewResult:
        return SkillViewResult(True, "skill")


def test_record_ptt_can_start_pristine_task(tmp_path, monkeypatch):
    monkeypatch.setattr(
        ptt_handlers,
        "HermesSkillViewAdapter",
        _ReadySkillAdapter,
    )
    skill_file = tmp_path / ".skill-loaded-ts"
    eng = _init_e2e(tmp_path, skill_file)
    ptt_path = eng / "state" / "ptt.md"
    ptt_path.write_text(
        ptt_path.read_text(encoding="utf-8").replace("| PT-010 | [~] |", "| PT-010 | [ ] |"),
        encoding="utf-8",
    )

    result = json.loads(
        TOOLS.handle_record_ptt(
            {
                "eng_dir": str(eng),
                "id": "PT-010",
                "status": "[~]",
                "note": "Start recon",
                "skill": "pentest",
                "technique": "recon",
            }
        )
    )
    assert result["status"] == "skill_prepared", result
    result = json.loads(
        TOOLS.handle_record_ptt(
            {
                "eng_dir": str(eng),
                "id": "PT-010",
                "status": "[~]",
                "note": "Start recon",
                "skill": "pentest",
                "technique": "recon",
            }
        )
    )
    assert result["status"] == "ok", result
    assert result["task_started"] is True
    assert ptt.find_active_task(ptt.parse_ptt(ptt_path)).id == "PT-010"


def test_first_command_requires_an_active_ptt_task(tmp_path):
    """The guard blocks target work until one PTT task is explicitly active."""
    skill_file = tmp_path / ".skill-loaded-ts"
    eng = _init_e2e(tmp_path, skill_file)
    ptt_path = eng / "state" / "ptt.md"
    ptt_path.write_text(
        ptt_path.read_text(encoding="utf-8").replace("| PT-010 | [~] |", "| PT-010 | [ ] |"),
        encoding="utf-8",
    )

    args = command.CheckCommandArgs(
        command="nmap -sV 10.10.10.10",
        phase="recon",
        eng_dir=str(eng),
        scope=str(eng / "scope" / "scope.yaml"),
        session_id="ts",
    )
    first = command.check_command(args)

    assert any(
        "exactly one" in error.lower() or "active task" in error.lower() for error in first.errors
    )


def test_multiple_active_ptt_tasks_block_target_execution(tmp_path):
    skill_file = tmp_path / ".skill-loaded-ts"
    eng = _init_e2e(tmp_path, skill_file)
    ptt_path = eng / "state" / "ptt.md"
    ptt_path.write_text(
        ptt_path.read_text(encoding="utf-8").replace("| PT-011 | [ ] |", "| PT-011 | [~] |"),
        encoding="utf-8",
    )
    result = command.check_command(
        command.CheckCommandArgs(
            command="nmap -sV 10.10.10.10",
            phase="recon",
            eng_dir=str(eng),
            scope=str(eng / "scope" / "scope.yaml"),
            session_id="ts",
        )
    )
    assert any(
        "exactly one" in error.lower() or "active task" in error.lower() for error in result.errors
    )


def test_exec_blocked_without_receipt_binding(monkeypatch, tmp_path):
    """Target execution remains denied when its receipt binding is absent."""
    _patch(monkeypatch, _cp(1, "BLOCK: skill load gate not satisfied\n"))
    out = json.loads(
        TOOLS.handle_exec(
            {
                "eng_dir": str(tmp_path),
                "scope": "s",
                "phase": "recon",
                "command": "nmap 1.2.3.4",
            }
        )
    )
    assert out["status"] in ("denied", "error")
    assert out["status"] in ("denied", "error")


def test_exec_ok_response_carries_formalization_hint(tmp_path):
    """A successful guarded execution must nudge hypothesis+FIND closure.

    The 15-proof -> 13-validated gap comes from found evidence never being
    formalized (Validated hypothesis + linked FIND citing the evidence).
    The exec response reminds the agent to close the loop in one step.
    """
    skill_file = tmp_path / ".skill-loaded-ts"
    eng = _init_e2e(tmp_path, skill_file)

    # Advance PTT to VULN_RESEARCH and add a hypothesis (mirrors the phase
    # handoff pattern in test_recon_does_not_require_hypothesis).
    ts = datetime.now(UTC).strftime("%Y-%m-%d %H:%M")
    (eng / "hypotheses.md").write_text(
        (eng / "hypotheses.md").read_text(encoding="utf-8")
        + (
            f"\n### H-001: Test endpoint exposed\n- **Status:** Candidate\n- **Phase:** VULN_RESEARCH\n"
            f"- **Target:** 10.10.10.10\n- **Updated:** {ts} UTC\n"
        ),
        encoding="utf-8",
    )
    ptt_path = eng / "state" / "ptt.md"
    ptt_path.write_text(
        ptt_path.read_text(encoding="utf-8")
        .replace("| PT-010 | [~] |", "| PT-010 | [x] |")
        .replace("| PT-030 | [ ] |", "| PT-030 | [~] |"),
        encoding="utf-8",
    )
    bind_active_task(eng, "ts")

    out = json.loads(
        TOOLS.handle_exec(
            {
                "eng_dir": str(eng),
                "phase": "vuln-research",
                "command": "curl -sS -i http://10.10.10.10/test",
                "label": "probe",
            }
        )
    )
    assert out["status"] == "ok", out
    assert out.get("next_action"), "ok exec response must carry a next_action hint"
    assert "violin_record_hypothesis" in out["next_action"]


def test_init_engagement_creates_compliant_artifacts(tmp_path):
    """`init-engagement` auto-creates a bootstrap-complete, guard-clean dir."""
    import yaml

    eng = tmp_path / "10.129.45.228-2026-07-08"
    rc = bootstrap.init_engagement(str(eng))
    assert rc == 0, "init-engagement should succeed"

    # A default engagement is structurally complete but deliberately remains
    # unapproved until the operator confirms authorisation.
    scope = yaml.safe_load((eng / "scope" / "scope.yaml").read_text(encoding="utf-8"))
    assert scope["targets"]["ip_addresses"] == ["10.129.45.228"]
    validation = command.validate_scope(eng / "scope" / "scope.yaml")
    assert any("authorisation.confirmed" in error for error in validation.errors)

    # bootstrap reports complete (exit 0) or REVIEW-only (pristine PTT is
    # legitimate on a brand-new engagement â€” no task touched yet).
    res = bootstrap.check_bootstrap(str(eng), auto_repair=False)
    assert int(res) in (0, 2), "bootstrap must be complete (or REVIEW for pristine PTT) after init"


def test_init_engagement_persists_explicit_session_id(tmp_path):
    eng = tmp_path / "session-bootstrap"

    assert bootstrap.init_engagement(str(eng), session_id="ctf-eu1") == 0
    assert state.resolve_session_id(eng) == "ctf-eu1"


def test_auto_repair_creates_missing_artifacts(tmp_path):
    """`check-bootstrap --auto-repair` self-heals missing required files."""
    import yaml

    eng = tmp_path / "10.10.10.5-2026-07-08"
    eng.mkdir(parents=True, exist_ok=True)  # empty dir, no artifacts

    # First pass with auto-repair creates every missing artifact.
    res = bootstrap.check_bootstrap(str(eng), auto_repair=True)
    # After self-heal, bootstrap must be clean (0) or REVIEW-only (2).
    assert int(res) in (0, 2), f"auto-repair should self-heal to clean, got {res}"

    # Artifacts now exist; a real operator still has to confirm authorisation.
    for rel in (
        "scope/scope.yaml",
        "state/ptt.md",
        "hypotheses.md",
        "state/history.md",
        "exploits",
        "evidence/exploitation",
    ):
        assert (eng / rel).exists(), f"auto-repair should create {rel}"
    yaml.safe_load((eng / "scope" / "scope.yaml").read_text(encoding="utf-8"))
    assert command.validate_scope(eng / "scope" / "scope.yaml").errors


def test_local_tmp_script_path_is_an_informational_reminder():
    result = command.check_local_artifact_paths("cat > /tmp/exploit.py <<'PY'\nprint('x')\nPY")
    assert result.infos == ["local script path uses /tmp; save it under $ENG_DIR/exploits instead"]


def test_exec_auto_records_history_but_requires_explicit_ptt_review(monkeypatch, tmp_path):
    """History is automatic; PTT freshness cannot be satisfied by execution."""
    monkeypatch.setenv("HERMES_YOLO_MODE", "1")
    skill_file = tmp_path / ".skill-loaded-ts"
    eng = _init_e2e(tmp_path, skill_file)
    args = {
        "eng_dir": str(eng),
        "scope": str(eng / "scope" / "scope.yaml"),
        "phase": "recon",
        "command": "nmap -sV 10.10.10.10",
        "skill_loaded_file": str(skill_file),
        "session_id": "ts",
    }

    ptt_path = eng / "state" / "ptt.md"
    ptt_before = ptt_path.read_text(encoding="utf-8")
    first = json.loads(TOOLS.handle_exec(args))
    assert first["status"] in ("ok", "approved", "review"), first
    assert "command=nmap -sV 10.10.10.10" in (eng / "state" / "history.md").read_text(
        encoding="utf-8"
    )
    assert ptt_path.read_text(encoding="utf-8") == ptt_before

    window = state.sync_credit_limit("recon")
    for i in range(2, window + 1):
        command_val = f"nmap -sV 10.10.10.10 -p {i}"
        out = json.loads(TOOLS.handle_exec({**args, "command": command_val}))
        assert out["status"] in ("ok", "approved", "review"), out

    blocked = json.loads(TOOLS.handle_exec({**args, "command": "nmap -sV 10.10.10.10 -p 99"}))
    assert blocked["status"] == "sync_required", blocked
    assert ptt_path.read_text(encoding="utf-8") == ptt_before

    # The guard captures the batch ID from pending state and appends its marker
    # to the PTT note; operators need not copy opaque internal IDs.
    from plugins.violin_guard.core import state as _state

    pending = _state.get_pending_sync(str(eng))
    assert pending, "a batch must be pending before review"
    batch_id = pending.get("batch_id")
    assert batch_id, "pending batch must carry a batch_id"

    history_text = (eng / "state" / "history.md").read_text(encoding="utf-8")
    assert history_text.count("exit_code=0 | command=nmap") == window

    reviewed = json.loads(
        TOOLS.handle_review_batch(
            {
                "eng_dir": str(eng),
                "id": "PT-010",
                "status": "[~]",
                "note": "batch reviewed",
            }
        )
    )
    assert reviewed["status"] == "ok", reviewed
    assert f"[reviewed-batch:{batch_id}]" in ptt_path.read_text(encoding="utf-8")
    resumed = json.loads(TOOLS.handle_exec({**args, "command": "nmap -sV 10.10.10.10 -p 99"}))
    assert resumed["status"] in ("ok", "approved", "review"), resumed


def test_exploitation_gets_bounded_window_then_requires_ptt_review(monkeypatch, tmp_path):
    """Exploit payloads may batch, but cannot self-certify PTT progress."""
    monkeypatch.setenv("HERMES_YOLO_MODE", "1")
    skill_file = tmp_path / ".skill-loaded-ts"
    eng = _init_e2e(tmp_path, skill_file)
    ptt_path = eng / "state" / "ptt.md"
    ptt_path.write_text(
        ptt_path.read_text(encoding="utf-8")
        .replace("| PT-010 | [~] |", "| PT-010 | [x] |")
        .replace("| PT-042 | [ ] |", "| PT-042 | [~] |"),
        encoding="utf-8",
    )
    bind_active_task(eng, "ts")
    # Create a real hypothesis (not in comment) for exploitation phase
    recorded = json.loads(
        TOOLS.handle_record_hypothesis(
            {
                "eng_dir": str(eng),
                "id": "001",
                "title": "scoped payload validation",
                "status": "Candidate",
                "phase": "EXPLOITATION",
                "target": "10.10.10.10",
                "service": "http",
                "port": "80",
                "cve_research": "web_search HTTP endpoint CVE; NVD; not applicable",
                "exploit_research": "web_search HTTP endpoint exploit; GitHub; no results",
            }
        )
    )
    assert recorded["status"] == "ok", recorded
    args = {
        "eng_dir": str(eng),
        "scope": str(eng / "scope" / "scope.yaml"),
        "phase": "exploitation",
        "skill_loaded_file": str(skill_file),
        "session_id": "ts",
    }

    ptt_before = ptt_path.read_text(encoding="utf-8")
    total = state.sync_credit_limit("exploitation")
    for i in range(total):
        command_val = f"curl http://10.10.10.10/probe?variant={i}"
        out = json.loads(TOOLS.handle_exec({**args, "command": command_val}))
        assert out["status"] in ("ok", "approved", "review"), out

    blocked = json.loads(
        TOOLS.handle_exec({**args, "command": "curl http://10.10.10.10/probe?variant=99"})
    )
    assert blocked["status"] == "sync_required", blocked
    assert ptt_path.read_text(encoding="utf-8") == ptt_before


def test_heartbeat_gate_every_n_commands(monkeypatch, tmp_path):
    """The interval command executes, then the next command waits for review."""
    monkeypatch.setenv("HERMES_YOLO_MODE", "1")
    skill_file = tmp_path / ".skill-loaded-ts"
    eng = _init_e2e(tmp_path, skill_file)
    args = {
        "eng_dir": str(eng),
        "scope": str(eng / "scope" / "scope.yaml"),
        "phase": "recon",
        "skill_loaded_file": str(skill_file),
        "session_id": "ts",
    }

    for _ in range(state.COMMAND_INTERVAL - 1):
        state.tick_command(str(eng))

    threshold = json.loads(TOOLS.handle_exec({**args, "command": "nmap -sV 10.10.10.10 -p 20"}))
    assert threshold["status"] == "ok", threshold
    assert threshold["executed"] is True
    assert state.read_counts(str(eng))["commands"] == state.COMMAND_INTERVAL
    assert state.has_heartbeat_pending(str(eng))

    blocked = json.loads(TOOLS.handle_exec({**args, "command": "nmap -sV 10.10.10.10 -p 21"}))
    assert blocked["status"] == "denied", blocked
    assert blocked["executed"] is False
    assert state.read_counts(str(eng))["commands"] == state.COMMAND_INTERVAL

    cleared = json.loads(TOOLS.handle_heartbeat_done({"eng_dir": str(eng)}))
    assert cleared["status"] == "ok", cleared

    resumed = json.loads(TOOLS.handle_exec({**args, "command": "nmap -sV 10.10.10.10 -p 21"}))
    assert resumed["status"] == "ok", resumed
    assert resumed["executed"] is True
    assert state.read_counts(str(eng))["commands"] == state.COMMAND_INTERVAL + 1


def test_message_ticks_are_diagnostic_and_do_not_trigger_heartbeat(monkeypatch, tmp_path):
    """LLM message volume must not create a stale guard lock."""
    skill_file = tmp_path / ".skill-loaded-ts"
    eng = _init_e2e(tmp_path, skill_file)

    # Build a session object via pre_llm_call (which increments message tick)
    from plugins.violin_guard.hooks import _pre_llm_call_hook

    for _ in range(100):
        _pre_llm_call_hook(session_id="ts", eng_dir=str(eng), phase="recon")

    assert not state.has_heartbeat_pending(str(eng))
    assert state.read_counts(str(eng))["messages"] == 100
