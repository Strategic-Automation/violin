from __future__ import annotations

from plugins.violin_guard.core.engagement import bootstrap, state
from plugins.violin_guard.gates import command
from tests.guard.integration.guard_fixture import (
    _fake_target_executor as _fake_target_executor,
)


def test_init_engagement_creates_compliant_artifacts(tmp_path):
    """`init-engagement` auto-creates a bootstrap-complete, guard-clean dir."""
    import yaml

    eng = tmp_path / "10.129.45.228-2026-07-08"
    rc = bootstrap.init_engagement(str(eng))
    assert rc == 0, "init-engagement should succeed"

    # A default engagement is structurally complete but deliberately remains
    # unapproved until the operator confirms authorisation.
    scope = yaml.safe_load((eng / "scope" / "scope.yaml").read_text(encoding="utf-8"))
    assert scope["targets"]["ip_addresses"] == ["10.129.45.228"]
    assert "rules_of_engagement" in scope
    assert "authorisation" in scope
    validation = command.validate_scope(eng / "scope" / "scope.yaml")
    assert any("authorisation.confirmed" in error for error in validation.errors)

    # Verify template contents copied from skills/pentest/templates after relocation
    hypo_content = (eng / "hypotheses.md").read_text(encoding="utf-8")
    assert "# Hypothesis Board" in hypo_content
    assert "### Hypothesis lifecycle" in hypo_content
    assert "## Active Theories" in hypo_content
    assert "## Observations" in hypo_content
    assert "## Decoy Trail" in hypo_content
    assert "## Research Log" in hypo_content
    assert "## Resolved Theories" in hypo_content

    ptt_content = (eng / "state" / "ptt.md").read_text(encoding="utf-8")
    assert "# Pentesting Task Tree" in ptt_content
    assert "## Task State Legend" in ptt_content
    assert "## Phase: SCOPING" in ptt_content
    assert "## Phase: RECON" in ptt_content
    assert "| PT-001 |" in ptt_content

    matrix_text = (eng / "state" / "coverage-matrix.yaml").read_text(encoding="utf-8")
    assert "Coverage matrix:" in matrix_text
    assert "coverage:" in matrix_text
    matrix_data = yaml.safe_load(matrix_text)
    assert "coverage" in matrix_data

    gates_text = (eng / "state" / "methodology-gates.yaml").read_text(encoding="utf-8")
    assert "Methodology gates:" in gates_text
    gates_data = yaml.safe_load(gates_text)
    assert "gates" in gates_data
    assert "authentication-session" in gates_data["gates"]

    hist_content = (eng / "state" / "history.md").read_text(encoding="utf-8")
    assert hist_content.startswith("# Command History")

    # bootstrap reports complete (exit 0) or REVIEW-only (pristine PTT is
    # legitimate on a brand-new engagement — no task touched yet).
    res = bootstrap.check_bootstrap(str(eng), auto_repair=False)
    assert int(res) in (0, 2), "bootstrap must be complete (or REVIEW for pristine PTT) after init"


def test_init_engagement_persists_explicit_session_id(tmp_path):
    eng = tmp_path / "session-bootstrap"

    assert bootstrap.init_engagement(str(eng), session_id="ctf-eu1") == 0
    assert state.resolve_session_id(eng) == "ctf-eu1"


def test_auto_repair_creates_missing_artifacts(tmp_path):
    """`check-bootstrap --auto-repair` self-heals missing required files."""
    import yaml

    eng = tmp_path / "10.10.10.5-2026-07-08"
    eng.mkdir(parents=True, exist_ok=True)  # empty dir, no artifacts

    # First pass with auto-repair creates every missing artifact.
    res = bootstrap.check_bootstrap(str(eng), auto_repair=True)
    # After self-heal, bootstrap must be clean (0) or REVIEW-only (2).
    assert int(res) in (0, 2), f"auto-repair should self-heal to clean, got {res}"

    # Artifacts now exist; a real operator still has to confirm authorisation.
    for rel in (
        "scope/scope.yaml",
        "state/ptt.md",
        "hypotheses.md",
        "state/history.md",
        "exploits",
        "evidence/exploitation",
    ):
        assert (eng / rel).exists(), f"auto-repair should create {rel}"
    assert "# Hypothesis Board" in (eng / "hypotheses.md").read_text(encoding="utf-8")
    assert "# Pentesting Task Tree" in (eng / "state" / "ptt.md").read_text(encoding="utf-8")
    assert "coverage:" in (eng / "state" / "coverage-matrix.yaml").read_text(encoding="utf-8")
    assert "gates:" in (eng / "state" / "methodology-gates.yaml").read_text(encoding="utf-8")
    yaml.safe_load((eng / "scope" / "scope.yaml").read_text(encoding="utf-8"))
    assert command.validate_scope(eng / "scope" / "scope.yaml").errors
