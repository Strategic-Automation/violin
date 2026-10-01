"""Research dispositions allow exploitation without claiming validation."""

import json
from pathlib import Path

import pytest
import yaml

from plugins.violin_guard.core.engagement import bootstrap, hypotheses, ptt
from plugins.violin_guard.core.engagement.disposition_policy import EXPECTED_METHODOLOGY_GATES
from plugins.violin_guard.handlers.ptt_gates import _validate_phase_exit
from plugins.violin_guard.handlers.ptt_handlers import _start_ptt_task
from plugins.violin_guard.registry import TOOL_DEFINITIONS, _validated_handler


@pytest.fixture
def researched_engagement(tmp_path: Path) -> Path:
    assert bootstrap.init_engagement(tmp_path, host="10.10.10.10") == 0
    scope_path = tmp_path / "scope/scope.yaml"
    scope = yaml.safe_load(scope_path.read_text(encoding="utf-8"))
    scope["engagement"] = {
        "audit_mode": True,
        "require_methodology_gates": True,
        "coverage_obligations": ["GET /synthetic"],
    }
    scope_path.write_text(yaml.safe_dump(scope), encoding="utf-8")
    (tmp_path / "state/coverage-matrix.yaml").write_text(
        "coverage:\n  get /synthetic:\n    status: tested\n"
        "    evidence_or_reason: H-001 read-only observation\n",
        encoding="utf-8",
    )
    gates = {
        name: {"status": "tested", "evidence_or_reason": "H-001 research observation"}
        for name in EXPECTED_METHODOLOGY_GATES
    }
    (tmp_path / "state/methodology-gates.yaml").write_text(
        yaml.safe_dump({"gates": gates}), encoding="utf-8"
    )
    definition = next(tool for tool in TOOL_DEFINITIONS if tool.name == "violin_record_hypothesis")
    response = json.loads(
        _validated_handler(definition)(
            {
                "eng_dir": str(tmp_path),
                "id": "001",
                "title": "Synthetic behavior hypothesis",
                "target": "10.10.10.10",
                "phase": "VULN_RESEARCH",
                "status": "Likely",
                "cve_research": "No applicable CVE found",
                "exploit_research": "Manual validation planned in EXPLOITATION",
            }
        )
    )
    assert response["status"] == "ok"
    assert response["hypothesis"]["cve_research"] == "No applicable CVE found"
    assert response["hypothesis"]["exploit_research"] == "Manual validation planned in EXPLOITATION"
    ptt.update_task(tmp_path / "state/ptt.md", "PT-030", "[~]", "Research")
    return tmp_path


def test_researched_likely_hypothesis_advances_without_becoming_validated(
    researched_engagement: Path,
) -> None:
    engagement = researched_engagement
    path = engagement / "state/ptt.md"
    _validate_phase_exit(engagement, "PT-030", "[x]")
    _start_ptt_task(path, ptt.parse_ptt(path), "PT-040", "[~]", "Validate H-001")
    tasks = {task.id: task for task in ptt.parse_ptt(path)}
    assert tasks["PT-030"].status == "[x]"
    assert tasks["PT-040"].status == "[~]"
    assert hypotheses.find_by_id(engagement / "hypotheses.md", "001").status == "Likely"
    assert not (engagement / "evidence/findings.jsonl").exists()


@pytest.mark.parametrize("missing", ["cve_research", "exploit_research"])
def test_likely_hypothesis_without_research_cannot_advance(
    researched_engagement: Path, missing: str
) -> None:
    engagement = researched_engagement
    hypotheses.update_hypothesis(engagement / "hypotheses.md", id="001", **{missing: ""})
    path = engagement / "state/ptt.md"
    before = path.read_bytes()
    with pytest.raises(ValueError, match="unresolved hypotheses: H-001"):
        _start_ptt_task(path, ptt.parse_ptt(path), "PT-040", "[~]", "Cannot advance")
    assert path.read_bytes() == before


def test_candidate_still_blocks_research_completion(researched_engagement: Path) -> None:
    engagement = researched_engagement
    hypotheses.update_hypothesis(engagement / "hypotheses.md", id="001", status="Candidate")
    with pytest.raises(ValueError, match="unresolved hypotheses: H-001"):
        _validate_phase_exit(engagement, "PT-030", "[x]")


@pytest.mark.parametrize("file", ["coverage-matrix.yaml", "methodology-gates.yaml"])
def test_likely_handoff_preserves_audit_dispositions(
    researched_engagement: Path, file: str
) -> None:
    engagement = researched_engagement
    (engagement / "state" / file).unlink()
    path = engagement / "state/ptt.md"
    before = path.read_bytes()
    with pytest.raises(ValueError, match=file):
        _start_ptt_task(path, ptt.parse_ptt(path), "PT-040", "[~]", "Cannot skip audit")
    assert path.read_bytes() == before


def test_handoff_does_not_let_likely_claim_validation_without_proof(
    researched_engagement: Path,
) -> None:
    engagement = researched_engagement
    board = engagement / "hypotheses.md"
    before = board.read_bytes()
    with pytest.raises(ValueError, match="runtime_evidence"):
        hypotheses.update_hypothesis(board, id="001", status="Validated")
    assert board.read_bytes() == before
