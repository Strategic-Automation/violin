"""Rendering, exit codes and PTT constructor compatibility."""

from dataclasses import asdict

import pytest

from plugins.violin_guard.core.engagement.ptt import PttTask, PttValidationResult
from plugins.violin_guard.core.results import GuardResult
from plugins.violin_guard.gates.command import CheckResult
from plugins.violin_guard.gates.hypothesis_gate import HypothesisResult
from plugins.violin_guard.gates.scope_gate import ScopeResult


@pytest.mark.parametrize("result_type", [GuardResult, CheckResult, HypothesisResult, ScopeResult])
def test_result_rendering_preserves_order_and_omits_hints(result_type, capsys):
    result = result_type(
        errors=["first", "second"], warnings=["caution"], infos=["ready"], hints=["private hint"]
    )
    result.print()
    assert capsys.readouterr().out == "BLOCK: first\nBLOCK: second\nREVIEW: caution\nOK: ready\n"


@pytest.mark.parametrize(
    "result_type", [GuardResult, CheckResult, HypothesisResult, ScopeResult, PttValidationResult]
)
@pytest.mark.parametrize(
    "errors,warnings,expected",
    [([], [], 0), ([], ["warn"], 2), (["error"], [], 1), (["error"], ["warn"], 1)],
)
def test_result_exit_precedence(result_type, errors, warnings, expected):
    assert result_type(errors=errors, warnings=warnings).exit_code() == expected


def test_ptt_result_retains_positional_constructor_and_serialized_fields():
    task = PttTask("PT-001", "[~]", "Recon", phase="RECON")
    result = PttValidationResult([], [], [task], task.id)
    assert result.tasks == [task]
    assert result.active_task == task.id
    assert list(asdict(result)) == ["errors", "warnings", "tasks", "active_task"]
