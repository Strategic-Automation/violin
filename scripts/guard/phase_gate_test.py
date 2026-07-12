"""Tests for the engagement phase-completion gate."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import pytest
import violin_guard as cli

from guard.phase_gate import (
    PHASE_ORDER,
    check_phase_gate,
    closure_requested_from_ptt,
)


@pytest.fixture
def eng(tmp_path: Path) -> Path:
    path = tmp_path / "eng"
    path.mkdir()
    return path


def _write(path: Path, content: str = "x") -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def _complete_engagement(eng: Path) -> None:
    _write(eng / "scope/scope.yaml")
    _write(eng / "scope/authorization.md")
    _write(eng / "state/ptt.md", _closed_ptt())
    _write(eng / "hypotheses.md", "- **Status:** Validated\n")
    _write(eng / "evidence/recon/nmap.txt")
    _write(eng / "evidence/vuln-research/research.md")
    _write(eng / "evidence/exploitation/proof.txt")
    _write(eng / "evidence/reporting/report.md", "# Report\n" + "finding evidence " * 5)
    _write(
        eng / "evidence/retrospective/retrospective.md",
        "# Retrospective\n" + "lesson learned " * 5,
    )
    _write(eng / "state/phase-summary.md")
    _write(eng / "state/checkpoint.json", json.dumps({"status": "COMPLETE"}))


def _closed_ptt() -> str:
    return """## Phase: REPORTING
| PT-050 | [x] | Evidence review | evidence |
| PT-051 | [x] | Fill report | evidence |

## Phase: RETROSPECTIVE
| PT-060 | [x] | Gap analysis | evidence |
| PT-061 | [x] | Lessons | evidence |
"""


def test_scope_files_required(eng: Path) -> None:
    ok, missing = check_phase_gate(eng, "SCOPING")
    assert not ok
    assert "scope/scope.yaml" in missing


def test_reporting_requires_nontrivial_report(eng: Path) -> None:
    _write(eng / "evidence/reporting/report.md", "short")
    ok, missing = check_phase_gate(eng, "REPORTING")
    assert not ok
    assert "evidence/reporting/report.md" in missing

    _write(eng / "evidence/reporting/report.md", "# Report\n" + "finding evidence " * 5)
    assert check_phase_gate(eng, "REPORTING") == (True, [])


def test_retrospective_requires_all_transition_artifacts(eng: Path) -> None:
    ok, missing = check_phase_gate(eng, "RETROSPECTIVE")
    assert not ok
    assert "evidence/retrospective/retrospective.md" in missing
    assert "state/phase-summary.md" in missing
    assert "state/checkpoint.json" in missing


def test_retrospective_passes_when_complete(eng: Path) -> None:
    _write(
        eng / "evidence/retrospective/retrospective.md",
        "# Retrospective\n" + "lesson learned " * 5,
    )
    _write(eng / "state/phase-summary.md")
    _write(eng / "state/checkpoint.json", json.dumps({"status": "COMPLETE"}))
    assert check_phase_gate(eng, "RETROSPECTIVE") == (True, [])


def test_checkpoint_status_must_be_complete(eng: Path) -> None:
    _write(
        eng / "evidence/retrospective/retrospective.md",
        "# Retrospective\n" + "lesson learned " * 5,
    )
    _write(eng / "state/phase-summary.md")
    _write(eng / "state/checkpoint.json", json.dumps({"status": "WIP"}))
    ok, missing = check_phase_gate(eng, "RETROSPECTIVE")
    assert not ok
    assert "state/checkpoint.json#status!=COMPLETE" in missing


def test_directory_phase_needs_a_nonempty_file(eng: Path) -> None:
    (eng / "evidence/recon").mkdir(parents=True)
    ok, missing = check_phase_gate(eng, "RECON")
    assert not ok
    assert "evidence/recon" in missing

    _write(eng / "evidence/recon/nested/nmap.txt")
    assert check_phase_gate(eng, "RECON") == (True, [])


def test_exploitation_requires_validated_hypothesis(eng: Path) -> None:
    _write(eng / "evidence/exploitation/proof.txt")
    _write(eng / "hypotheses.md", "- **Status:** Likely\n")
    ok, missing = check_phase_gate(eng, "EXPLOITATION")
    assert not ok
    assert "hypotheses.md#status!=Validated/Verified" in missing

    _write(eng / "hypotheses.md", "- **Status:** Verified\n")
    assert check_phase_gate(eng, "EXPLOITATION") == (True, [])


def test_reporting_and_retrospective_rows_trigger_closure_gate(eng: Path) -> None:
    _write(eng / "state/ptt.md", _closed_ptt())
    assert closure_requested_from_ptt(eng)

    _write(
        eng / "state/ptt.md",
        _closed_ptt().replace("| PT-061 | [x]", "| PT-061 | [ ]"),
    )
    assert not closure_requested_from_ptt(eng)


def test_check_phase_gate_cli_returns_one_and_lists_missing(eng: Path, capsys) -> None:
    rc = cli.cmd_check_phase_gate(argparse.Namespace(eng_dir=str(eng), phase="REPORTING"))
    output = capsys.readouterr().out
    assert rc == 1
    assert "REVIEW: phase gate not satisfied for REPORTING" in output
    assert "MISSING: evidence/reporting/report.md" in output


def test_close_cli_checks_every_phase(eng: Path, capsys) -> None:
    rc = cli.cmd_close(argparse.Namespace(eng_dir=str(eng)))
    output = capsys.readouterr().out
    assert rc == 1
    for phase in PHASE_ORDER:
        assert f"  {phase}:" in output

    _complete_engagement(eng)
    assert cli.cmd_close(argparse.Namespace(eng_dir=str(eng))) == 0


def test_sync_done_reviews_closure_gaps_without_clearing_lock(
    eng: Path, monkeypatch, capsys
) -> None:
    _write(eng / "state/ptt.md", _closed_ptt())
    _write(eng / "state/history.md", "history")
    cli.sync_state.mark_pending_sync(str(eng), "command", "retrospective")
    monkeypatch.setattr(cli.sync_state, "artifacts_are_fresh", lambda *_: True)

    rc = cli.cmd_sync_done(argparse.Namespace(eng_dir=str(eng), close=False))
    output = capsys.readouterr().out
    assert rc == 2
    assert "REVIEW: engagement closure blocked" in output
    assert "evidence/reporting/report.md" in output
    assert cli.sync_state.has_pending_sync(str(eng)) is not None


def test_sync_done_clears_lock_after_all_phase_gates_pass(eng: Path, monkeypatch) -> None:
    _complete_engagement(eng)
    _write(eng / "state/history.md", "history")
    cli.sync_state.mark_pending_sync(str(eng), "command", "retrospective")
    monkeypatch.setattr(cli.sync_state, "artifacts_are_fresh", lambda *_: True)

    rc = cli.cmd_sync_done(argparse.Namespace(eng_dir=str(eng), close=False))
    assert rc == 0
    assert cli.sync_state.has_pending_sync(str(eng)) is None


def test_sync_done_close_flag_checks_gate_without_pending_lock(eng: Path, capsys) -> None:
    rc = cli.cmd_sync_done(argparse.Namespace(eng_dir=str(eng), close=True))
    assert rc == 2
    assert "REVIEW: engagement closure blocked" in capsys.readouterr().out
