from __future__ import annotations

import json
from datetime import UTC, datetime

from plugins.violin_guard import handlers as TOOLS
from plugins.violin_guard.core.engagement import state
from tests.guard.integration.guard_fixture import (
    _append_active_theories,
    _cp,
    _init_e2e,
    _patch,
)
from tests.guard.integration.guard_fixture import (
    _fake_target_executor as _fake_target_executor,
)
from tests.guard.receipt_fixture import bind_active_task


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


def test_exec_ok_response_carries_hypothesis_review_hint(tmp_path):
    """A successful guarded execution nudges the immediate evidence review."""
    skill_file = tmp_path / ".skill-loaded-ts"
    eng = _init_e2e(tmp_path, skill_file)

    # Advance PTT to VULN_RESEARCH and add a hypothesis (mirrors the phase
    # handoff pattern in test_recon_does_not_require_hypothesis).
    ts = datetime.now(UTC).strftime("%Y-%m-%d %H:%M")
    _append_active_theories(
        eng / "hypotheses.md",
        f"### H-001: Test endpoint exposed\n- **Status:** Candidate\n- **Phase:** VULN_RESEARCH\n"
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
    from plugins.violin_guard.core.engagement import state as _state

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

    with state.workflow_lock(eng):
        state._mutate_runtime(
            eng,
            lambda runtime: setattr(runtime.counts, "commands", state.COMMAND_INTERVAL - 1),
        )

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
