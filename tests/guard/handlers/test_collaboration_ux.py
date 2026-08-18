"""Regression coverage for the guard's model-visible collaboration surface."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from plugins.violin_guard import (
    bootstrap,
    history,
    hypotheses,
    ptt,
    state,
)
from plugins.violin_guard import (
    handlers as service,
)
from plugins.violin_guard.core.skill_receipts import SkillViewResult, get_binding
from plugins.violin_guard.handlers import ptt_handlers
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


def _prepare_finding_review(eng: Path) -> None:
    hypotheses.update_hypothesis(
        eng / "hypotheses.md",
        id="001",
        title="HTTP listener is externally reachable",
        status="Validated",
        phase="RECON",
        target="10.10.10.10",
        runtime_evidence="evidence/executions/batch-command.stdout.txt",
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


class _ReadySkillAdapter:
    def view(self, *_args, **_kwargs) -> SkillViewResult:
        return SkillViewResult(True, "pentest review")


def test_review_batch_does_not_replace_execution_skill_binding(tmp_path: Path, monkeypatch) -> None:
    eng = _engagement(tmp_path)
    _pending_batch(eng)
    original_binding = get_binding(eng, "PT-010")
    monkeypatch.setattr(
        ptt_handlers,
        "HermesSkillViewAdapter",
        _ReadySkillAdapter,
    )
    args = {
        "eng_dir": str(eng),
        "id": "PT-010",
        "status": "[~]",
        "note": "Reviewed service discovery evidence",
        "skill": "pentest",
        "outcome": "progress",
        "evidence_paths": ["evidence/executions/batch-command.stdout.txt"],
        "next_action": "enumerate HTTP",
        "next_technique": "http-enumeration",
    }

    prepared = json.loads(service.handle_review_batch(args))
    assert prepared["status"] == "skill_prepared"
    reviewed = json.loads(service.handle_review_batch(args))

    assert reviewed["status"] == "ok"
    assert reviewed["binding_task_id"] is None
    assert get_binding(eng, "PT-010") == original_binding


def test_review_batch_conflicting_skill_binds_to_binding_skill_not_deadlock(
    tmp_path: Path, monkeypatch
) -> None:
    """An explicit skill that conflicts with the delivered binding must not deadlock.

    Passing a skill that differs from the task's binding skill (e.g. a phase-default
    like 'identity-auth' while the binding is 'pentest') must resolve to the binding
    skill and succeed, instead of rejecting whichever is passed.
    """
    eng = _engagement(tmp_path)
    _pending_batch(eng)
    original_binding = get_binding(eng, "PT-010")
    assert original_binding["skill"] == "pentest"
    monkeypatch.setattr(
        ptt_handlers,
        "HermesSkillViewAdapter",
        _ReadySkillAdapter,
    )
    args = {
        "eng_dir": str(eng),
        "id": "PT-010",
        "status": "[~]",
        "note": "Reviewed service discovery evidence",
        "skill": "identity-auth",  # conflicts with the binding skill 'pentest'
        "outcome": "progress",
        "evidence_paths": ["evidence/executions/batch-command.stdout.txt"],
        "next_action": "enumerate HTTP",
        "next_technique": "http-enumeration",
    }

    reviewed = json.loads(service.handle_review_batch(args))
    assert reviewed["status"] == "ok"
    assert get_binding(eng, "PT-010") == original_binding


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


def test_review_batch_creates_finding_without_fp_check_preparation(tmp_path: Path) -> None:
    eng = _engagement(tmp_path)
    _pending_batch(eng)
    hypotheses.update_hypothesis(
        eng / "hypotheses.md",
        id="001",
        title="HTTP listener is externally reachable",
        status="Validated",
        phase="RECON",
        target="10.10.10.10",
        runtime_evidence="evidence/executions/batch-command.stdout.txt",
    )

    result = json.loads(
        service.handle_review_batch(
            {
                "eng_dir": str(eng),
                "id": "PT-010",
                "status": "[~]",
                "note": "Reviewed the HTTP service receipt",
                "finding": {
                    "hypothesis_id": "H-001",
                    "title": "Exposed HTTP service",
                    "severity": "Info",
                    "description": "An HTTP listener is reachable on the approved target.",
                    "impact": "The service contributes to the externally reachable attack surface.",
                    "remediation": "Confirm the listener is intended.",
                },
            }
        )
    )

    assert result["status"] == "ok"
    assert result["released"] is True
    assert result["finding"]["finding_id"] == "FIND-001"
    finding = eng / result["finding"]["path"]
    assert finding.is_file()
    text = finding.read_text(encoding="utf-8")
    assert "# FIND-001: Exposed HTTP service" in text
    assert "batch-command.stdout.txt" in text


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


def test_update_hypothesis_supports_discipline_fields(tmp_path: Path) -> None:
    hyp_file = tmp_path / "hypotheses.md"
    hyp_file.write_text(
        "# Hypothesis Board\n\n## Active Theories\n\n",
        encoding="utf-8",
    )
    h = hypotheses.update_hypothesis(
        hyp_file,
        id="001",
        title="SQLi in authentication form",
        status="Candidate",
        confidence="0.8",
        timebox="4 tool batches",
        cheapest_test="' OR 1=1 --",
        kill_criteria="Response status 404 or no error output",
        next_step="Run sqlmap probe",
        linked_findings="FIND-001",
    )
    assert h.confidence == "0.8"
    assert h.timebox == "4 tool batches"
    assert h.cheapest_test == "' OR 1=1 --"
    assert h.kill_criteria == "Response status 404 or no error output"
    assert h.next_step == "Run sqlmap probe"
    assert h.linked_findings == "FIND-001"

    parsed = hypotheses.parse_hypotheses(hyp_file)
    assert len(parsed) == 1
    assert parsed[0].confidence == "0.8"
    assert parsed[0].cheapest_test == "' OR 1=1 --"

    text = hyp_file.read_text(encoding="utf-8")
    assert "- **Confidence:** 0.8" in text
    assert "- **Timebox:** 4 tool batches" in text
    assert "- **Cheapest test:** ' OR 1=1 --" in text
    assert "- **Kill criteria:** Response status 404 or no error output" in text


def test_update_hypothesis_preserves_board_sections(tmp_path: Path) -> None:
    template_path = ROOT / "skills" / "pentest" / "templates" / "hypothesis-board.md"
    hyp_file = tmp_path / "hypotheses.md"
    hyp_file.write_text(template_path.read_text(encoding="utf-8"), encoding="utf-8")

    h = hypotheses.update_hypothesis(
        hyp_file,
        id="001",
        title="Command injection in search endpoint",
        status="Candidate",
    )
    assert h.id == "001"
    text = hyp_file.read_text(encoding="utf-8")
    assert "## Active Theories" in text
    assert "### H-001: Command injection in search endpoint" in text
    assert "## Observations (ungrouped)" in text
    assert "## Investigation Chains" in text
    assert "## Decoy Trail (killed approaches — do NOT re-enter)" in text
    assert "## Research Log" in text
    assert "## Resolved Theories" in text


def test_update_hypothesis_keeps_distinct_ids_isolated(tmp_path: Path) -> None:
    hyp_file = tmp_path / "hypotheses.md"
    hyp_file.write_text("# Hypothesis Board\n\n", encoding="utf-8")
    evidence = tmp_path / "evidence" / "executions" / "access-control.json"
    evidence.parent.mkdir(parents=True)
    evidence.write_text('{"status":"completed"}\n', encoding="utf-8")
    hypotheses.update_hypothesis(
        hyp_file,
        id="H-021",
        title="Existing access-control finding",
        status="Validated",
        runtime_evidence="evidence/executions/access-control.json",
    )
    hypotheses.update_hypothesis(
        hyp_file,
        id="H-030",
        title="CVE research candidate",
        status="Candidate",
        cve_research="Vendor advisory checked; no relevant CVE.",
    )

    records = {item.id: item for item in hypotheses.parse_hypotheses(hyp_file)}
    assert set(records) == {"021", "030"}
    assert records["021"].title == "Existing access-control finding"
    assert records["021"].status == "Validated"
    assert records["030"].title == "CVE research candidate"
    assert records["030"].cve_research.startswith("Vendor advisory")
