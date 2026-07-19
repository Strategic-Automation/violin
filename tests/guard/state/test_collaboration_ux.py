"""Regression coverage for the guard's model-visible collaboration surface."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path

import pytest

from plugins.violin_guard import bootstrap, findings, history, hypotheses, ptt, service, state
from plugins.violin_guard.skill_receipts import (
    SkillViewResult,
    complete_delivery,
    prepare_delivery,
    prepare_review_readiness,
)
from tests.guard.receipt_fixture import bind_active_task

ROOT = Path(__file__).resolve().parents[3]


def _engagement(tmp_path: Path) -> Path:
    eng = tmp_path / "engagement"
    assert bootstrap.init_engagement(eng, host="10.10.10.10") == 0
    scope = eng / "scope" / "scope.yaml"
    scope.write_text(
        scope.read_text(encoding="utf-8").replace("confirmed: false", "confirmed: true"),
        encoding="utf-8",
    )
    ptt_path = eng / "state" / "ptt.md"
    ptt_path.write_text(
        ptt_path.read_text(encoding="utf-8").replace("| PT-010 | [ ] |", "| PT-010 | [~] |"),
        encoding="utf-8",
    )
    state.record_session_id(eng, "test-session")
    (eng / "state" / ".skill-loaded-test-session").write_text(
        "skill-loaded: pentest\n", encoding="utf-8"
    )
    bind_active_task(eng, "test-session")
    return eng


def _pending_batch(eng: Path) -> None:
    command = "nmap -sV 10.10.10.10"
    (eng / "evidence" / "executions").mkdir(parents=True, exist_ok=True)
    manifest = eng / "evidence" / "executions" / "batch-command.json"
    stdout = eng / "evidence" / "executions" / "batch-command.stdout.txt"
    stdout.write_text("80/tcp open http\n", encoding="utf-8")
    state.atomic_json(
        manifest,
        {
            "command": command,
            "phase": "RECON",
            "completed_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
            "exit_code": 0,
            "evidence_paths": {
                "manifest": manifest.relative_to(eng).as_posix(),
                "stdout": stdout.relative_to(eng).as_posix(),
            },
        },
    )
    history.append_history(eng, command, "RECON", 0, manifest.relative_to(eng).as_posix())
    state.mark_pending_sync(eng, command, "RECON", "PT-010")


def _prepare_finding_review(eng: Path, finding_id: str = "FIND-001") -> None:
    hypotheses.update_hypothesis(
        eng / "hypotheses.md",
        id="001",
        title="HTTP listener is externally reachable",
        status="Validated",
        phase="RECON",
        target="10.10.10.10",
        runtime_evidence="evidence/executions/batch-command.stdout.txt",
    )
    reserved = prepare_delivery(
        eng,
        session_id="test-session",
        skill="fp-check",
        bundle_digest="sha256:" + "b" * 64,
        phase="RETROSPECTIVE",
    )
    if reserved.owner:
        reserved = complete_delivery(eng, reserved, SkillViewResult(True, content="fp-check"))
    evidence = findings._batch_evidence(eng, state.get_pending_sync(eng))
    prepare_review_readiness(
        eng,
        finding_id=finding_id,
        evidence_digest="sha256:" + sha256("\n".join(sorted(evidence)).encode()).hexdigest(),
        delivery_id=reserved.id,
    )


def test_create_task_inserts_into_requested_phase_table(tmp_path: Path) -> None:
    path = tmp_path / "ptt.md"
    path.write_text(
        (ROOT / "skills" / "pentest" / "templates" / "ptt.md").read_text(encoding="utf-8"),
        encoding="utf-8",
    )

    created = ptt.create_task(
        path,
        "PT-099",
        "Validate requested exploit",
        "EXPLOITATION",
        "evidence/exploitation/",
    )

    assert created.phase == "EXPLOITATION"
    text = path.read_text(encoding="utf-8")
    assert text.index("| PT-099 |") < text.index("## Phase: REPORTING")
    row = next(line for line in text.splitlines() if "| PT-099 |" in line)
    assert len(row.strip().strip("|").split("|")) == 7


def test_status_explains_current_phase_pending_commands_and_skill(tmp_path: Path) -> None:
    eng = _engagement(tmp_path)
    _pending_batch(eng)

    result = json.loads(service.handle_status({"eng_dir": str(eng)}))

    assert result["status"] == "ok"
    assert result["current_task"] == "PT-010"
    assert result["current_phase"] == "RECON"
    assert result["pending_batch"]["commands"][0]["required_phase"] == "RECON"
    assert result["phase_requirements"]["EXPLOITATION"]["sync_window"] == 20
    assert result["skill"]["binding_ready"] is True
    assert result["skill"]["legacy_marker_status"] in {"absent", "obsolete"}


@pytest.mark.parametrize("task_status", ["[~]", "[x]", "[!]", "[-]"])
def test_review_batch_updates_ptt_and_clears_lock(tmp_path: Path, task_status: str) -> None:
    eng = _engagement(tmp_path)
    _pending_batch(eng)
    _prepare_finding_review(eng)

    result = json.loads(
        service.handle_review_batch(
            {
                "eng_dir": str(eng),
                "id": "PT-010",
                "status": task_status,
                "note": "Reviewed service discovery evidence; HTTP is the next task input",
            }
        )
    )

    assert result["status"] == "ok"
    assert result["task_status"] == task_status
    assert result["released"] is True
    assert not state.has_pending_sync(eng)
    assert "reviewed-batch:" in (eng / "state" / "ptt.md").read_text(encoding="utf-8")


def test_review_batch_creates_finding_from_current_batch_receipts(tmp_path: Path) -> None:
    eng = _engagement(tmp_path)
    _pending_batch(eng)
    _prepare_finding_review(eng)

    result = json.loads(
        service.handle_review_batch(
            {
                "eng_dir": str(eng),
                "id": "PT-010",
                "status": "[~]",
                "note": "Reviewed the HTTP service receipt",
                "finding": {
                    "finding_id": "FIND-001",
                    "hypothesis_id": "H-001",
                    "title": "Exposed HTTP service",
                    "severity": "Info",
                    "description": "An HTTP listener is reachable on the approved target.",
                    "impact": "The service contributes to the externally reachable attack surface.",
                    "remediation": (
                        "Confirm the listener is intended and restrict it when unnecessary."
                    ),
                },
            }
        )
    )

    assert result["status"] == "ok"
    finding = eng / result["finding"]["path"]
    assert result["finding_path"] == result["finding"]["path"]
    assert finding.is_file()
    text = finding.read_text(encoding="utf-8")
    assert "batch-command.stdout.txt" in text
    assert "## Remediation" in text


@pytest.mark.parametrize(
    ("mutation", "expected"),
    [
        ("history", "exact history"),
        ("task", "does not match batch task"),
        ("phase", "not phase-compatible"),
        ("finding", "must be non-empty"),
    ],
)
def test_invalid_review_batch_leaves_sync_lock_active(
    tmp_path: Path, mutation: str, expected: str
) -> None:
    eng = _engagement(tmp_path)
    _pending_batch(eng)
    args = {
        "eng_dir": str(eng),
        "id": "PT-010",
        "status": "[~]",
        "note": "Review receipt",
    }
    if mutation == "history":
        (eng / "state" / "history.md").write_text("# History\n", encoding="utf-8")
    elif mutation == "task":
        args["id"] = "PT-011"
    elif mutation == "phase":
        sync_path = eng / "state" / "sync.json"
        sync_data = state.read_json(sync_path)
        sync_data["pending"]["commands"][0]["phase"] = "EXPLOITATION"
        state.atomic_json(sync_path, sync_data)
    else:
        args["finding"] = {
            "title": "",
            "severity": "Info",
            "description": "Description",
            "impact": "Impact",
            "remediation": "Remediation",
        }

    result = json.loads(service.handle_review_batch(args))

    assert result["status"] == "blocked"
    assert expected in result["error"]
    assert result["next_action"]
    assert state.has_pending_sync(eng)


def test_review_batch_retry_reuses_marker_and_finding_after_partial_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    eng = _engagement(tmp_path)
    _pending_batch(eng)
    _prepare_finding_review(eng)
    args = {
        "eng_dir": str(eng),
        "id": "PT-010",
        "status": "[~]",
        "note": "Reviewed HTTP receipt",
        "finding": {
            "finding_id": "FIND-001",
            "hypothesis_id": "H-001",
            "title": "Exposed HTTP service",
            "severity": "Info",
            "description": "An HTTP listener is reachable.",
            "impact": "The service increases the reachable attack surface.",
            "remediation": "Restrict the listener when it is not required.",
        },
    }
    real_clear = state.clear_pending_sync

    def fail_clear(_eng_dir: str | Path) -> None:
        raise OSError("simulated clear failure")

    monkeypatch.setattr(state, "clear_pending_sync", fail_clear)
    first = json.loads(service.handle_review_batch(args))
    assert first["status"] == "blocked"
    assert state.has_pending_sync(eng)

    monkeypatch.setattr(state, "clear_pending_sync", real_clear)
    retry = json.loads(service.handle_review_batch(args))

    assert retry["status"] == "ok"
    assert retry["finding"]["reused"] is True
    ptt_text = (eng / "state" / "ptt.md").read_text(encoding="utf-8")
    assert ptt_text.count("[reviewed-batch:") == 1
    assert len(list((eng / "evidence" / "findings").glob("FIND-*.md"))) == 1
    assert not state.has_pending_sync(eng)


def test_sync_windows_are_phase_aware() -> None:
    assert state.sync_credit_limit("RECON") == 10
    assert state.sync_credit_limit("EXPLOITATION") == 20
    assert state.sync_credit_limit("PRIVESC") == 20
