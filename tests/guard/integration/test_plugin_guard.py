import importlib.util
import json
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path

import pytest

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


def _load_sub(name, path):
    spec = importlib.util.spec_from_file_location("vgpkg." + name, path)
    mod = importlib.util.module_from_spec(spec)
    mod.__package__ = "vgpkg"
    sys.modules["vgpkg." + name] = mod
    spec.loader.exec_module(mod)
    return mod


# Load the plugin as a real package so `from . import utils` resolves.
_PLUGIN = ROOT / "plugins/violin_guard"
_PKG = importlib.util.spec_from_file_location("vgpkg", _PLUGIN / "__init__.py")
pkg = importlib.util.module_from_spec(_PKG)
pkg.__path__ = [str(_PLUGIN)]
pkg.__package__ = "vgpkg"
sys.modules["vgpkg"] = pkg

TOOLS = _load_sub("tools", _PLUGIN / "service.py")

# Import core modules from the new location
from plugins.violin_guard import bootstrap, command, execution, history, hypotheses, ptt, state
from plugins.violin_guard.targets import extract_target_candidates


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
        remaining = state.spend_sync_credit(str(engagement))
        # Mirror real execution: tick command counter, mark pending sync, set heartbeat if interval reached
        from plugins.violin_guard.phases import normalize_phase, suppresses_heartbeat

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

    # Patch the exact module used by the separately loaded vgpkg.tools facade.
    monkeypatch.setattr(TOOLS.execution, "execute", fake_execute)
    monkeypatch.setattr(execution, "execute", fake_execute)
    assert TOOLS.execution.execute is fake_execute


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
    return eng


def test_meta_loaded():
    # Current plugin surface: handle_* command entrypoints registered.
    for name in (
        "handle_exec",
        "handle_check_command",
        "handle_sync_done",
        "handle_record_ptt",
        "handle_record_hypothesis",
    ):
        assert hasattr(TOOLS, name), f"plugin must expose {name}"


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
            skill_loaded_file=str(skill_file),
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
            skill_loaded_file=str(skill_file),
            session_id="ts",
        )
    )
    assert any("requires at least one hypothesis" in error.lower() for error in research.errors)

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
    research2 = command.check_command(
        command.CheckCommandArgs(
            command="nmap -sV 10.10.10.10",
            phase="vuln-research",
            eng_dir=str(eng),
            scope=str(eng / "scope" / "scope.yaml"),
            skill_loaded_file=str(skill_file),
            session_id="ts",
        )
    )
    assert not research2.errors
    assert not any("hypothesis" in warning.lower() for warning in research2.warnings)

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
            skill_loaded_file=str(skill_file),
            session_id="ts",
        )
    )
    assert any("hypothesis guard:" in warning for warning in research3.warnings)


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


def test_exploitation_requires_cve_and_exploit_research_attempts(tmp_path):
    (tmp_path / "hypotheses.md").write_text(
        """### H-001: Queue service validation
- **Target:** 10.129.47.140:1515
- **Status:** Likely
- **Phase:** VULN_RESEARCH
- **CVE Research:** web_search queue service 1515 CVE; NVD; no results
""",
        encoding="utf-8",
    )

    blocked = command.check_hypothesis_freshness(
        tmp_path, command.Phase.EXPLOITATION, "python3 exploit.py 10.129.47.140 1515"
    )
    assert any("Exploit Research" in error for error in blocked.errors)

    (tmp_path / "hypotheses.md").write_text(
        (tmp_path / "hypotheses.md").read_text(encoding="utf-8")
        + "- **Exploit Research:** web_search queue service 1515 PoC; GitHub; source unavailable\n",
        encoding="utf-8",
    )
    allowed = command.check_hypothesis_freshness(
        tmp_path, command.Phase.EXPLOITATION, "python3 exploit.py 10.129.47.140 1515"
    )
    assert not allowed.errors, allowed.errors


def test_record_ptt_can_start_pristine_task(tmp_path):
    skill_file = tmp_path / ".skill-loaded-ts"
    eng = _init_e2e(tmp_path, skill_file)
    ptt_path = eng / "state" / "ptt.md"
    ptt_path.write_text(
        ptt_path.read_text(encoding="utf-8").replace("| PT-010 | [~] |", "| PT-010 | [ ] |"),
        encoding="utf-8",
    )

    result = json.loads(
        TOOLS.handle_record_ptt(
            {"eng_dir": str(eng), "id": "PT-010", "status": "[~]", "note": "Start recon"}
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
        skill_loaded_file=str(skill_file),
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
            skill_loaded_file=str(skill_file),
            session_id="ts",
        )
    )
    assert any(
        "exactly one" in error.lower() or "active task" in error.lower() for error in result.errors
    )


def test_exec_blocked_without_skill_load(monkeypatch, tmp_path):
    """Skill-load gate: check-command BLOCKs when the SKILL.md marker is absent,
    and handle_exec honours that BLOCK (status 'denied')."""
    from plugins.violin_guard.command import check_skill_load

    # Real gate: missing marker file => BLOCK (error).
    gate = check_skill_load(Path(tmp_path / "no-skill-loaded"), "test", mandatory=True)
    assert gate.errors, "missing skill-loaded marker must BLOCK"

    # handle_exec must translate a BLOCKed check-command into 'denied'.
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


def test_skill_load_gate_identifies_stale_session_marker(tmp_path):
    from plugins.violin_guard.command import check_skill_load

    state = tmp_path / "state"
    state.mkdir()
    (state / ".skill-loaded-old-session").write_text("skill-loaded: test\n", encoding="utf-8")

    gate = check_skill_load(tmp_path, "current-session", mandatory=True)

    assert gate.errors
    assert ".skill-loaded-old-session" in gate.errors[0]
    assert str(state / ".skill-loaded-current-session") in gate.errors[0]


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

    window = state.DEFAULT_SYNC_CREDIT
    for i in range(2, window + 1):
        command_val = f"nmap -sV 10.10.10.10 -p {i}"
        out = json.loads(TOOLS.handle_exec({**args, "command": command_val}))
        assert out["status"] in ("ok", "approved", "review"), out

    blocked = json.loads(TOOLS.handle_exec({**args, "command": "nmap -sV 10.10.10.10 -p 99"}))
    assert blocked["status"] == "sync_required", blocked
    assert ptt_path.read_text(encoding="utf-8") == ptt_before

    # The guard captures the batch ID from pending state and appends its marker
    # to the PTT note; operators need not copy opaque internal IDs.
    from plugins.violin_guard import state as _state

    pending = _state.get_pending_sync(str(eng))
    assert pending, "a batch must be pending before review"
    batch_id = pending.get("batch_id")
    assert batch_id, "pending batch must carry a batch_id"

    history_text = (eng / "state" / "history.md").read_text(encoding="utf-8")
    assert history_text.count("exit_code=0 | command=nmap") == window

    reviewed = json.loads(
        TOOLS.handle_record_ptt(
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
    synced = json.loads(TOOLS.handle_sync_done({"eng_dir": str(eng)}))
    assert synced["status"] == "ok", synced
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
    total = state.DEFAULT_SYNC_CREDIT
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

    threshold = json.loads(
        TOOLS.handle_exec({**args, "command": "nmap -sV 10.10.10.10 -p 20"})
    )
    assert threshold["status"] == "ok", threshold
    assert threshold["executed"] is True
    assert state.read_counts(str(eng))["commands"] == state.COMMAND_INTERVAL
    assert state.has_heartbeat_pending(str(eng))

    blocked = json.loads(
        TOOLS.handle_exec({**args, "command": "nmap -sV 10.10.10.10 -p 21"})
    )
    assert blocked["status"] == "denied", blocked
    assert blocked["executed"] is False
    assert state.read_counts(str(eng))["commands"] == state.COMMAND_INTERVAL

    cleared = json.loads(TOOLS.handle_heartbeat_done({"eng_dir": str(eng)}))
    assert cleared["status"] == "ok", cleared

    resumed = json.loads(
        TOOLS.handle_exec({**args, "command": "nmap -sV 10.10.10.10 -p 21"})
    )
    assert resumed["status"] == "ok", resumed
    assert resumed["executed"] is True
    assert state.read_counts(str(eng))["commands"] == state.COMMAND_INTERVAL + 1


def test_message_tick_triggers_heartbeat(monkeypatch, tmp_path):
    """Every MESSAGE_INTERVAL calls, heartbeat is required."""
    skill_file = tmp_path / ".skill-loaded-ts"
    eng = _init_e2e(tmp_path, skill_file)

    # Build a session object via pre_llm_call (which increments message tick)
    from plugins.violin_guard import _pre_llm_call_hook

    for _ in range(state.MESSAGE_INTERVAL - 1):
        _pre_llm_call_hook(session_id="ts", eng_dir=str(eng), phase="recon")

    assert _pre_llm_call_hook(session_id="ts", eng_dir=str(eng), phase="recon") is None
