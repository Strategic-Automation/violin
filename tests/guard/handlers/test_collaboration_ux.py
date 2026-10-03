"""Regression coverage for the guard's model-visible collaboration surface."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from plugins.violin_guard import handlers as service
from plugins.violin_guard.core.engagement import ptt, state
from plugins.violin_guard.core.skills.skill_receipts import SkillViewResult, get_binding
from plugins.violin_guard.handlers import ptt_review
from tests.guard.receipt_fixture import bind_active_task

ROOT = Path(__file__).resolve().parents[3]


from tests.guard.handlers._collaboration_helpers import _engagement, _pending_batch


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


@pytest.mark.parametrize("note", ["XSS payload <img onerror>", "link <a href={o}>", "JS a || b"])
def test_review_batch_with_markup_note_releases_pending_lock(tmp_path: Path, note: str) -> None:
    eng = _engagement(tmp_path)
    _pending_batch(eng)

    result = json.loads(
        service.handle_review_batch(
            {"eng_dir": str(eng), "id": "PT-010", "status": "[x]", "note": note}
        )
    )

    assert result["status"] == "ok", result
    assert not state.has_pending_sync(eng)
    reviewed = next(task for task in ptt.parse_ptt(eng / "state" / "ptt.md") if task.id == "PT-010")
    assert reviewed.status == "[x]"
    assert note in reviewed.note
    assert "[reviewed-batch:" in reviewed.note


class _ReadySkillAdapter:
    def view(self, *_args, **_kwargs) -> SkillViewResult:
        return SkillViewResult(True, "pentest review")


def test_review_batch_does_not_replace_execution_skill_binding(tmp_path: Path, monkeypatch) -> None:
    eng = _engagement(tmp_path)
    _pending_batch(eng)
    original_binding = get_binding(eng, "PT-010")
    monkeypatch.setattr(
        ptt_review,
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
        ptt_review,
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


def test_review_batch_resolves_the_bound_hypothesis_route_not_the_phase_default(
    tmp_path: Path, monkeypatch
) -> None:
    """One route per task: the binding's hypothesis decides, so tools agree.

    The task is bound to a class-routed skill ('identity-auth' for the
    authorization class) while the phase default would be 'pentest'. Reviewing
    the batch with that same skill - the one violin_record_ptt demanded - used to
    be rejected as "not permitted; expected 'pentest' because phase default", so
    no single skill satisfied both tools.

    The board also records a free-text candidate source ('internet-search') that
    maps to no route: deriving the context must filter it out rather than pass it
    to the policy, which would reject the call with "unknown candidate source".
    """
    eng = _engagement(tmp_path)
    _pending_batch(eng)
    (eng / "hypotheses.md").write_text(
        "# Hypotheses\n\n"
        "## Active Theories\n\n"
        "### H-007: Cross-account order access\n"
        "- **Status:** Candidate\n"
        "- **Vuln Class:** authorization\n"
        "- **Candidate Source:** internet-search\n",
        encoding="utf-8",
    )
    (eng / "state" / ".skill-loaded-test-session").write_text(
        "skill-loaded: identity-auth\n", encoding="utf-8"
    )
    bind_active_task(
        eng,
        "test-session",
        skill="identity-auth",
        hypothesis_id="H-007",
        vulnerability_class="authorization",
    )
    monkeypatch.setattr(ptt_review, "HermesSkillViewAdapter", _ReadySkillAdapter)

    status = json.loads(service.handle_status({"eng_dir": str(eng)}))
    assert status["skill"]["route_candidates"] == ["identity-auth"]

    args = {
        "eng_dir": str(eng),
        "id": "PT-010",
        "status": "[~]",
        "note": "Reviewed cross-account order access evidence",
        "skill": "identity-auth",
        "outcome": "progress",
        "evidence_paths": ["evidence/executions/batch-command.stdout.txt"],
        "next_action": "confirm object ownership boundary",
        "next_technique": "idor",
    }

    prepared = json.loads(service.handle_review_batch(dict(args)))
    assert prepared["status"] == "skill_prepared"
    reviewed = json.loads(service.handle_review_batch(dict(args)))

    assert reviewed["status"] == "ok"
    assert get_binding(eng, "PT-010")["skill"] == "identity-auth"


@pytest.mark.parametrize(
    ("mutation", "expected"),
    [
        ("history", "exact history"),
        ("task", "does not match batch task"),
        ("phase", "not phase-compatible"),
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

        def change_pending_phase(runtime):
            runtime.sync.pending.commands[0].phase = "EXPLOITATION"

        state._mutate_runtime(eng, change_pending_phase)

    result = json.loads(service.handle_review_batch(args))

    assert result["status"] == "blocked"
    assert expected in result["error"]
    assert result["next_action"]
    assert state.has_pending_sync(eng)


def test_review_batch_retry_reuses_marker_after_partial_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    eng = _engagement(tmp_path)
    _pending_batch(eng)
    args = {
        "eng_dir": str(eng),
        "id": "PT-010",
        "status": "[~]",
        "note": "Reviewed HTTP receipt",
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
    ptt_text = (eng / "state" / "ptt.md").read_text(encoding="utf-8")
    assert ptt_text.count("[reviewed-batch:") == 1
    assert not state.has_pending_sync(eng)


def test_sync_windows_are_phase_aware() -> None:
    assert state.sync_credit_limit("RECON") == 10
    assert state.sync_credit_limit("EXPLOITATION") == 20
    assert state.sync_credit_limit("PRIVESC") == 20
