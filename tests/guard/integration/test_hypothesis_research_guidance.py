from __future__ import annotations

from datetime import UTC, datetime

from plugins.violin_guard.gates import command
from tests.guard.integration.guard_fixture import (
    _append_active_theories,
    _init_e2e,
)
from tests.guard.integration.guard_fixture import (
    _fake_target_executor as _fake_target_executor,
)
from tests.guard.receipt_fixture import bind_active_task


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
    _append_active_theories(
        eng / "hypotheses.md",
        f"### H-001: SMB share exposed\n- **Status:** Candidate\n- **Phase:** VULN_RESEARCH\n"
        f"- **Target:** 10.10.10.10\n- **Updated:** {ts} UTC",
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
    _append_active_theories(
        eng / "hypotheses.md",
        f"### H-002: Old hypothesis\n- **Status:** Candidate\n- **Phase:** VULN_RESEARCH\n"
        f"- **Target:** 10.10.10.10\n- **Updated:** {old_ts} UTC",
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
    assert any("hypothesis guard:" in hint for hint in research3.hints)


def test_exploit_phase_does_not_gate_on_research(tmp_path):
    """Online research is encouraged but never a hard gate on exploit execution.

    Neither named nor unnamed exploit commands may be blocked for missing
    CVE/Exploit Research rows — a per-hypothesis research requirement degrades
    into a bookkeeping tax that walls off the whole exploit phase.
    """
    skill_file = tmp_path / ".skill-loaded-ts"
    eng = _init_e2e(tmp_path, skill_file)
    ts = datetime.now(UTC).strftime("%Y-%m-%d %H:%M")
    _append_active_theories(
        eng / "hypotheses.md",
        f"### H-001: JWT alg none\n- **Status:** Validated\n- **Phase:** EXPLOITATION\n"
        f"- **Target:** duck-store.escape.tech\n- **CVE Research:** NVD queried; no CVE\n"
        f"- **Exploit Research:** ExploitDB; none applicable\n- **Updated:** {ts} UTC\n\n"
        f"### H-002: No research done\n- **Status:** Candidate\n- **Phase:** EXPLOITATION\n"
        f"- **Target:** duck-store.escape.tech\n- **Updated:** {ts} UTC",
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


def test_exploitation_hints_when_research_missing_but_does_not_block(tmp_path):
    (tmp_path / "hypotheses.md").write_text(
        """# Hypothesis Board

## Active Theories

### H-001: Queue service validation
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
    assert any("hint:" in h.lower() and "exploit research" in h.lower() for h in result.hints)

    (tmp_path / "hypotheses.md").write_text(
        (tmp_path / "hypotheses.md").read_text(encoding="utf-8")
        + "- **Exploit Research:** web_search queue service 1515 PoC; GitHub; source unavailable\n",
        encoding="utf-8",
    )
    allowed = command.check_hypothesis_freshness(
        tmp_path, command.Phase.EXPLOITATION, "python3 exploit.py 10.129.47.140 1515"
    )
    assert not any("hint:" in h.lower() and "exploit research" in h.lower() for h in allowed.hints)


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
        "## Phase: EXPLOITATION\n\n"
        "| ID | Status | Task | Notes |\n|---|---|---|---|\n"
        "| PT-001 | [~] | Exploit Task | testing H-002 |\n",
        encoding="utf-8",
    )
    # H-001 has research; active task links H-002 which has NO research.
    (tmp_path / "hypotheses.md").write_text(
        "# Hypothesis Board\n\n## Active Theories\n\n"
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
    assert any("hint:" in h.lower() and "H-002" in h for h in res.hints)
