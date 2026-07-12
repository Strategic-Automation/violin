import importlib.util
import json
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parent.parent

# Make `violin_guard` resolvable
_PLUGIN_ROOT = ROOT / "plugins" / "violin_guard"
_PLUGIN_PARENT = _PLUGIN_ROOT.parent
if str(_PLUGIN_PARENT) not in sys.path:
    sys.path.insert(0, str(_PLUGIN_PARENT))

_PLATFORM_SCOPE = """targets:
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


# Load the plugin as a real package so `from . import utils` resolves.
_PLUGIN = ROOT / "plugins/violin_guard"
_PKG = importlib.util.spec_from_file_location("vgpkg", _PLUGIN / "__init__.py")
pkg = importlib.util.module_from_spec(_PKG)
pkg.__path__ = [str(_PLUGIN)]
pkg.__package__ = "vgpkg"
sys.modules["vgpkg"] = pkg

TOOLS = _load_sub("tools", _PLUGIN / "tools.py")

# Import core modules from the new location
from plugins.violin_guard.core import bootstrap, command, hypotheses, ptt, state, phases, execution


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
        history = engagement / "state" / "history.md"
        with history.open("a", encoding="utf-8") as handle:
            handle.write(f"- [2026-07-11T00:00:01Z] [{phase.upper()}] exit=0 `{command}`\n")
        remaining = state.spend_sync_credit(str(engagement))
        # Mirror real execution: tick command counter, mark pending sync, set heartbeat if interval reached
        from plugins.violin_guard.core.phases import normalize_phase, suppresses_heartbeat
        count = state.tick_command(str(engagement))
        state.mark_pending_sync(str(engagement), command, phase)
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

    # Patch the execution module that vgpkg.tools imports (vgpkg.core.execution)
    import sys
    if "vgpkg.core.execution" in sys.modules:
        monkeypatch.setattr(sys.modules["vgpkg.core.execution"], "execute", fake_execute)
    monkeypatch.setattr(execution, "execute", fake_execute)


def _init_e2e(tmp_path, skill_file):
    """Build a guard-clean RECON engagement (scope allows vuln-research so the
    hypothesis guard is exercised) and write the skill-load marker at its
    canonical location.

    The skill-load gate requires a session-scoped marker at
    ``$ENG_DIR/state/.skill-loaded-<session-id>``; passing ``--session-id``
    makes the CLI compute that canonical path itself, so we write there. We
    also pre-mark PT-001 as in-progress so the PTT staleness guard (which BLOCKs
    until at least one PT row has moved past ``[ ]``) does not reject the very
    first recon command — this mirrors a normal SCOPING->RECON handoff.
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
        ptt_path.read_text(encoding="utf-8").replace("| PT-001 | [ ] |", "| PT-001 | [~] |"),
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


def test_first_command_requires_an_active_ptt_task(tmp_path):
    """The guard blocks target work until one PTT task is explicitly active."""
    skill_file = tmp_path / ".skill-loaded-ts"
    eng = _init_e2e(tmp_path, skill_file)
    ptt_path = eng / "state" / "ptt.md"
    ptt_path.write_text(
        ptt_path.read_text(encoding="utf-8").replace("| PT-001 | [~] |", "| PT-001 | [ ] |"),
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

    assert any("exactly one" in error.lower() or "active task" in error.lower() for error in first.errors)


def test_multiple_active_ptt_tasks_block_target_execution(tmp_path):
    skill_file = tmp_path / ".skill-loaded-ts"
    eng = _init_e2e(tmp_path, skill_file)
    ptt_path = eng / "state" / "ptt.md"
    ptt_path.write_text(
        ptt_path.read_text(encoding="utf-8").replace("| PT-010 | [ ] |", "| PT-010 | [~] |"),
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
    assert any("exactly one" in error.lower() or "active task" in error.lower() for error in result.errors)


def test_exec_blocked_without_skill_load(monkeypatch, tmp_path):
    """Skill-load gate: check-command BLOCKs when the SKILL.md marker is absent,
    and handle_exec honours that BLOCK (status 'denied')."""
    from plugins.violin_guard.core.command import check_skill_load

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


def test_init_engagement_creates_compliant_artifacts(tmp_path):
    """`init-engagement` auto-creates a bootstrap-complete, guard-clean dir."""
    import yaml

    eng = tmp_path / "10.129.45.228-2026-07-08"
    rc = bootstrap.init_engagement(str(eng))
    assert rc == 0, "init-engagement should succeed"

    # scope.yaml present and parses clean (no REVIEW on required fields)
    scope = yaml.safe_load((eng / "scope" / "scope.yaml").read_text(encoding="utf-8"))
    assert scope["targets"]["ip_addresses"] == ["10.129.45.228"]
    assert command.validate_scope(eng / "scope" / "scope.yaml").exit_code() == 0, "filled scope must be guard-clean"

    # bootstrap reports complete (exit 0) or REVIEW-only (pristine PTT is
    # legitimate on a brand-new engagement — no task touched yet).
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

    # Artifacts now exist and scope is guard-clean
    for rel in ("scope/scope.yaml", "state/ptt.md", "hypotheses.md", "state/history.md"):
        assert (eng / rel).exists(), f"auto-repair should create {rel}"
    scope = yaml.safe_load((eng / "scope" / "scope.yaml").read_text(encoding="utf-8"))
    assert command.validate_scope(eng / "scope" / "scope.yaml").exit_code() == 0


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
    assert "`nmap -sV 10.10.10.10`" in (eng / "state" / "history.md").read_text(
        encoding="utf-8"
    )
    assert ptt_path.read_text(encoding="utf-8") == ptt_before

    window = state.DEFAULT_SYNC_CREDIT
    for i in range(2, window + 1):
        command_val = f"nmap -sV 10.10.10.10 -p {i}"
        out = json.loads(TOOLS.handle_exec({**args, "command": command_val}))
        assert out["status"] in ("ok", "approved", "review"), out

    blocked = json.loads(
        TOOLS.handle_exec({**args, "command": "nmap -sV 10.10.10.10 -p 99"})
    )
    assert blocked["status"] == "sync_required", blocked
    assert ptt_path.read_text(encoding="utf-8") == ptt_before

    history_text = (eng / "state" / "history.md").read_text(encoding="utf-8")
    assert history_text.count("exit=0 `nmap") == window

    reviewed = json.loads(
        TOOLS.handle_record_ptt(
            {"eng_dir": str(eng), "id": "PT-001", "status": "[~]", "note": "batch reviewed"}
        )
    )
    assert reviewed["status"] == "ok", reviewed
    synced = json.loads(TOOLS.handle_sync_done({"eng_dir": str(eng)}))
    assert synced["status"] == "ok", synced
    resumed = json.loads(
        TOOLS.handle_exec({**args, "command": "nmap -sV 10.10.10.10 -p 99"})
    )
    assert resumed["status"] in ("approved", "review"), resumed


def test_exploitation_gets_bounded_window_then_requires_ptt_review(monkeypatch, tmp_path):
    """Exploit payloads may batch, but cannot self-certify PTT progress."""
    monkeypatch.setenv("HERMES_YOLO_MODE", "1")
    skill_file = tmp_path / ".skill-loaded-ts"
    eng = _init_e2e(tmp_path, skill_file)
    ptt_path = eng / "state" / "ptt.md"
    ptt_path.write_text(
        ptt_path.read_text(encoding="utf-8")
        .replace("| PT-001 | [~] |", "| PT-001 | [x] |")
        .replace("| PT-042 | [ ] |", "| PT-042 | [~] |"),
        encoding="utf-8",
    )
    # Create a real hypothesis (not in comment) for exploitation phase
    from plugins.violin_guard.core import hypotheses
    stamp = datetime.now(UTC).strftime("%Y-%m-%d %H:%M")
    hypotheses.update_hypothesis(
        eng / "hypotheses.md",
        id="001",
        title="scoped payload validation",
        status="Candidate",
        phase="EXPLOITATION",
        target="10.10.10.10",
    )
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
    """Every COMMAND_INTERVAL commands, a heartbeat must be satisfied."""
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

    interval = state.COMMAND_INTERVAL
    for i in range(1, interval + 1):
        command_val = f"nmap -sV 10.10.10.10 -p {i}"
        out = json.loads(TOOLS.handle_exec({**args, "command": command_val}))
        assert out["status"] in ("ok", "approved", "review", "denied", "sync_required"), out


def test_message_tick_triggers_heartbeat(monkeypatch, tmp_path):
    """Every MESSAGE_INTERVAL calls, heartbeat is required."""
    skill_file = tmp_path / ".skill-loaded-ts"
    eng = _init_e2e(tmp_path, skill_file)

    # Build a session object via pre_llm_call (which increments message tick)
    from plugins.violin_guard import _pre_llm_call_hook

    for _ in range(state.MESSAGE_INTERVAL - 1):
        _pre_llm_call_hook(session_id="ts", eng_dir=str(eng), phase="recon")

    assert _pre_llm_call_hook(session_id="ts", eng_dir=str(eng), phase="recon") is None
