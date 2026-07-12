import importlib.util
import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

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

from guard.bootstrap import init_engagement, check_bootstrap  # noqa: E402
from guard.core import validate_scope_data  # noqa: E402
from guard import sync as sync_state  # noqa: E402
from guard.bootstrap import check_skill_loaded  # noqa: E402


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
    ptt.write_text(ptt.read_text(encoding="utf-8").replace(
        "| PT-001 | [ ] |", "| PT-001 | [~] |"), encoding="utf-8")
    return eng


def test_meta_loaded():
    # Current plugin surface: handle_* command entrypoints registered.
    for name in ("handle_exec", "handle_check_command", "handle_sync_done",
                 "handle_record_ptt", "handle_record_hypothesis", "handle_record_history"):
        assert hasattr(TOOLS, name), f"plugin must expose {name}"


def test_exec_blocked_without_skill_load(monkeypatch, tmp_path):
    """Skill-load gate: check-command BLOCKs when the SKILL.md marker is absent,
    and handle_exec honours that BLOCK (status 'denied')."""
    from guard.freshness import check_skill_load_gate

    # Real gate: missing marker file => BLOCK (error).
    gate = check_skill_load_gate(str(tmp_path / "no-skill-loaded"), mandatory=True)
    assert gate.errors, "missing skill-loaded marker must BLOCK"

    # handle_exec must translate a BLOCKed check-command into 'denied'.
    _patch(monkeypatch, _cp(1, "BLOCK: skill load gate not satisfied\n"))
    out = json.loads(TOOLS.handle_exec({
        "eng_dir": str(tmp_path), "scope": "s", "phase": "recon",
        "command": "nmap 1.2.3.4",
    }))
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
    """End-to-end doc-sync gate: after approving cmd1, cmd2 is BLOCKED
    (status 'denied' + 'block' reason) until ptt.md / history.md /
    hypothesis-board.md are updated & sync_done clears the lock."""
    skill_file = tmp_path / ".skill-loaded-ts"
    eng = _init_e2e(tmp_path, skill_file)
    d = str(eng)
    args = dict(eng_dir=d, scope=str(eng / "scope" / "scope.yaml"),
                phase="recon", command="nmap -sV 10.10.10.10",
                skill_loaded_file=str(skill_file), session_id="ts")

    # cmd1 allowed (status 'approved' or a non-blocking 'review'); the enforced
    # path arms a pending-sync on either allow (rc 0 or 2).
    out1 = json.loads(TOOLS.handle_exec(args))
    assert out1["status"] in ("approved", "review"), out1
    assert out1["status"] != "denied", out1
    assert sync_state.has_pending_sync(d) is not None, "doc-sync gate must arm after approve"

    # cmd2 attempted before syncing -> the doc-sync gate blocks it. The handler
    # returns status 'sync_required' (NOT 'denied') with a 'hint' telling the
    # operator to run the command, update artifacts, then call sync-done.
    # NOTE: the gate must NOT silently clear the lock just because record-history
    # hasn't run yet (that was the original bug) — the pending-sync lock stays
    # armed during the normal pending window, so cmd2 is correctly blocked here.
    out2 = json.loads(TOOLS.handle_exec(args))
    assert out2["status"] in ("denied", "sync_required"), out2
    assert "not synced" in (out2.get("raw") or "").lower() or any(
        "not synced" in b for b in out2.get("block", [])
    ), out2

    # Update artifacts so the prior command's ts is covered.
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M")
    ptt = eng / "state" / "ptt.md"
    ptt.write_text(ptt.read_text(encoding="utf-8").replace(
        "| PT-001 | [ ] |", f"| PT-001 | [~] |") + f"\n*Last updated: {ts} UTC*\n")
    hist = eng / "state" / "history.md"
    hist.write_text(hist.read_text(encoding="utf-8") + f"\n- [{ts}] nmap -sV 10.10.10.10\n")
    hb = eng / "hypotheses.md"
    hb.write_text(hb.read_text(encoding="utf-8") + (
        f"\n### H-001: seed\n- **Status:** Candidate\n- **Phase:** RECON\n"
        f"- **Target:** 10.10.10.10\n- **Updated:** {ts} UTC\n"))

    # sync_done should now clear the lock.
    out3 = json.loads(TOOLS.handle_sync_done({"eng_dir": d}))
    assert out3["status"] == "ok", out3
    assert sync_state.has_pending_sync(d) is None, "sync-done must clear the lock"

    # Now cmd2 proceeds (a distinct command so the stuck-loop guard stays quiet).
    out4 = json.loads(TOOLS.handle_exec({**args, "command": "gobuster dir -u http://10.10.10.10"}))
    assert out4["status"] in ("approved", "review"), out4


def test_heartbeat_gate_every_n_commands(monkeypatch, tmp_path):
    """After COMMAND_INTERVAL approved commands, the NEXT violin_exec is BLOCKED
    (status 'denied' + heartbeat block reason) until heartbeat-done clears it."""
    skill_file = tmp_path / ".skill-loaded-ts"
    eng = _init_e2e(tmp_path, skill_file)
    d = str(eng)
    interval = UTILS.COMMAND_INTERVAL
    base = dict(eng_dir=d, scope=str(eng / "scope" / "scope.yaml"),
                phase="recon", skill_loaded_file=str(skill_file), session_id="ts")

    # Approve `interval` distinct commands, satisfying the doc-sync lock between each.
    for i in range(interval):
        cmd = f"nmap -p {i} 10.10.10.10"
        out = json.loads(TOOLS.handle_exec({**base, "command": cmd}))
        assert out["status"] in ("approved", "review"), f"cmd {i+1} should pass: {out}"
        # satisfy the per-command doc-sync gate
        ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M")
        ptt = eng / "state" / "ptt.md"
        ptt.write_text(ptt.read_text(encoding="utf-8") + f"\n*Last updated: {ts} UTC*\n")
        hist = eng / "state" / "history.md"
        hist.write_text(hist.read_text(encoding="utf-8") + f"\n- [{ts}] {cmd}\n")
        hb = eng / "hypotheses.md"
        hb.write_text(hb.read_text(encoding="utf-8") + f"\n- **Updated:** {ts} UTC\n")
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
    blocked = json.loads(TOOLS.handle_exec({
        "eng_dir": d, "scope": str(eng / "scope" / "scope.yaml"),
        "phase": "recon", "command": "nmap 1.2.3.7",
    }))
    assert blocked["status"] == "denied"
    assert any("heartbeat" in b for b in blocked["block"]), blocked


def test_resolve_eng_dir_converges_all_forms():
    """resolve_eng_dir makes every caller form land on the SAME absolute tree.

    Root-cause fix (issue 1): the skill historically passed a relative
    ``engagements/<host>-<date>`` while the plugin resolved against CWD, so the
    two trees diverged. Every form below must resolve to ENG_ROOT/<host>-<date>.
    """
    from guard.core import ENG_ROOT, resolve_eng_dir
    from pathlib import Path

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
    assert not (eng / "state" / ".violin_pending_sync.json").exists(), \
        "orphaned lock file must be cleared"

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
    ptt.write_text(ptt.read_text(encoding="utf-8").replace(
        "| PT-001 | [ ] |", "| PT-001 | [x] |"), encoding="utf-8")
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
    out = json.loads(TOOLS.handle_check_command({
        "eng_dir": d, "scope": str(eng / "scope" / "scope.yaml"),
        "phase": "REPORTING", "command": "search_files $ENG_DIR/evidence",
    }))
    assert out["status"] == "block", f"yolo must NOT approve a close-out block (got {out['status']}): {out}"
    assert out["status"] != "ok", f"yolo must NOT auto-approve a close-out block: {out}"
    assert any("close-out gate" in b for b in out["block"]), out


def test_closeout_permits_artifact_creation(monkeypatch, tmp_path):
    """The exact command that PRODUCES reporting/report.md is exempted so the
    agent can create the file the gate requires (no deadlock)."""
    from guard.closeout import check_closeout

    eng = _build_reporting_eng(tmp_path)
    res = check_closeout(str(eng), "REPORTING",
                         'write_file path="$ENG_DIR/reporting/report.md" content="..."')
    assert not res.errors, f"artifact-producing command must be exempt: {res.errors}"


def test_closeout_passes_when_artifacts_present(monkeypatch, tmp_path):
    """Once report.md, phase-summary.md, CVSS, and a Research Log entry exist,
    the REPORTING gate is clean (no block)."""
    from guard.closeout import check_closeout

    eng = _build_reporting_eng(tmp_path)
    (eng / "state" / "phase-summary.md").write_text(
        "# Phase summary\nPTT status: complete.\n", encoding="utf-8")
    (eng / "reporting").mkdir(parents=True, exist_ok=True)
    (eng / "reporting" / "report.md").write_text(
        "# Report\n## Findings\n- Severity: Critical — CVSS:3.1 AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H (9.8)\n",
        encoding="utf-8")
    hb = eng / "hypotheses.md"
    hb.write_text(hb.read_text(encoding="utf-8") + "\n## Research Log\n- **RES-001:** Trigger: scan -> Searched: NVD -> Result: CVE-2024-0001\n")
    res = check_closeout(str(eng), "REPORTING", "search_files $ENG_DIR/evidence")
    assert not res.errors, f"complete artifacts must pass: {res.errors}"


def test_retrospective_blocks_without_retro_md(monkeypatch, tmp_path):
    """RETROSPECTIVE without retrospective.md must BLOCK even with report done."""
    from guard.closeout import check_closeout

    eng = _build_reporting_eng(tmp_path)
    (eng / "state" / "phase-summary.md").write_text("# Phase summary\n", encoding="utf-8")
    (eng / "reporting").mkdir(parents=True, exist_ok=True)
    (eng / "reporting" / "report.md").write_text(
        "# Report\n## Findings\nSeverity: Critical — CVSS:3.1 AV:N/AC:L (9.8)\n", encoding="utf-8")
    res = check_closeout(str(eng), "RETROSPECTIVE", "search_files $ENG_DIR/evidence")
    assert res.errors, "missing retrospective.md must BLOCK"
    assert res.exit_code() == 1
