from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from plugins.violin_guard.core.engagement import bootstrap
from plugins.violin_guard.handlers.ptt_gates import (
    _methodology_gate_errors,
    _validate_phase_exit,
)


def _valid_gates_yaml() -> str:
    cells = "\n".join(
        f"  {g}:\n    status: tested\n    evidence_or_reason: 'evidence/vuln-research/{g}.txt probe'"
        for g in (
            "information-gathering",
            "configuration-deployment",
            "authentication-session",
            "authorization",
            "input-validation",
            "error-handling",
            "cryptography",
            "business-logic",
            "client-side",
            "api-testing",
        )
    )
    return f"gates:\n{cells}\n"


def test_bootstrap_creates_methodology_gates_template(tmp_path: Path) -> None:
    engagement = tmp_path / "engagement"
    assert bootstrap.init_engagement(engagement, host="10.10.10.10") == 0
    gates = engagement / "state" / "methodology-gates.yaml"
    assert gates.is_file()
    text = gates.read_text(encoding="utf-8")
    assert "gates:" in text
    assert "authentication-session" in text
    assert "evidence_or_reason:" in text


def test_methodology_gates_required_when_flag_set(tmp_path: Path) -> None:
    engagement = tmp_path / "engagement"
    assert bootstrap.init_engagement(engagement, host="10.10.10.10") == 0
    scope = engagement / "scope" / "scope.yaml"
    scope.write_text(
        scope.read_text(encoding="utf-8")
        + "\nengagement:\n  audit_mode: true\n  require_methodology_gates: true\n",
        encoding="utf-8",
    )
    gates = engagement / "state" / "methodology-gates.yaml"
    gates.unlink()  # simulate the agent never creating it
    with pytest.raises(ValueError, match="methodology-gates.yaml exists"):
        _validate_phase_exit(engagement, "PT-030", "[x]")


def test_methodology_gates_accepts_dispositioned_gates(tmp_path: Path) -> None:
    engagement = tmp_path / "engagement"
    assert bootstrap.init_engagement(engagement, host="10.10.10.10") == 0
    scope = engagement / "scope" / "scope.yaml"
    scope.write_text(
        scope.read_text(encoding="utf-8")
        + "\nengagement:\n  audit_mode: true\n  require_methodology_gates: true\n",
        encoding="utf-8",
    )
    gates = engagement / "state" / "methodology-gates.yaml"
    gates.write_text(_valid_gates_yaml(), encoding="utf-8")
    assert not _methodology_gate_errors(
        engagement, yaml.safe_load(scope.read_text(encoding="utf-8"))
    )


def test_methodology_gates_rejects_missing_categories(tmp_path: Path) -> None:
    engagement = tmp_path / "engagement"
    assert bootstrap.init_engagement(engagement, host="10.10.10.10") == 0
    scope = engagement / "scope" / "scope.yaml"
    scope.write_text(
        scope.read_text(encoding="utf-8")
        + "\nengagement:\n  audit_mode: true\n  require_methodology_gates: true\n",
        encoding="utf-8",
    )
    gates = engagement / "state" / "methodology-gates.yaml"
    gates.write_text(
        "gates:\n  authentication-session:\n    status: tested\n    evidence_or_reason: 'evidence/x.txt'\n",
        encoding="utf-8",
    )
    errors = _methodology_gate_errors(engagement, yaml.safe_load(scope.read_text(encoding="utf-8")))
    assert any("undispositioned methodology gates" in err for err in errors)


def test_methodology_gates_rejects_test_without_evidence(tmp_path: Path) -> None:
    engagement = tmp_path / "engagement"
    assert bootstrap.init_engagement(engagement, host="10.10.10.10") == 0
    scope = engagement / "scope" / "scope.yaml"
    scope.write_text(
        scope.read_text(encoding="utf-8")
        + "\nengagement:\n  audit_mode: true\n  require_methodology_gates: true\n",
        encoding="utf-8",
    )
    gates = engagement / "state" / "methodology-gates.yaml"
    gates.write_text(
        _valid_gates_yaml().replace("'evidence/vuln-research/", "'not-an-artifact/"),
        encoding="utf-8",
    )
    errors = _methodology_gate_errors(engagement, yaml.safe_load(scope.read_text(encoding="utf-8")))
    assert any("tested without evidence" in err for err in errors)
