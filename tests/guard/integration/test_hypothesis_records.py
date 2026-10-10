from __future__ import annotations

import pytest

from plugins.violin_guard.core.engagement import hypotheses
from plugins.violin_guard.gates import command
from tests.guard.integration.guard_fixture import (
    _fake_target_executor as _fake_target_executor,
)


def test_hypothesis_id_and_target_are_canonicalized_without_false_collisions(tmp_path):
    path = tmp_path / "hypotheses.md"
    path.write_text("# Hypothesis Board\n\n## Active Theories\n\n", encoding="utf-8")

    record = hypotheses.update_hypothesis(
        path,
        in_scope_hosts={"10.10.15.65"},
        id="H-001",
        title="Scoped endpoint test",
        status="Candidate",
        phase="EXPLOITATION",
        target="http://10.10.15.65:4445",
        cve_research="web_search scoped endpoint CVE; NVD; not applicable",
        exploit_research="web_search scoped endpoint exploit; GitHub; no results",
    )

    assert record.id == "001"
    text = path.read_text(encoding="utf-8")
    assert "### H-001: Scoped endpoint test" in text
    assert "## Active Theories" in text

    result = command.check_hypothesis_freshness(
        tmp_path,
        command.Phase.EXPLOITATION,
        "bash -c 'echo test > /dev/tcp/10.10.15.65/4445' > 01-nmap-full.txt",
    )
    assert not result.errors, result.errors


def test_hypothesis_refuses_syntax_uncertain_rejection(tmp_path):
    path = tmp_path / "hypotheses.md"
    with pytest.raises(ValueError, match="must remain active for re-test"):
        hypotheses.update_hypothesis(
            path,
            in_scope_hosts={"10.10.15.65"},
            id="001",
            title="PJL file download",
            status="Rejected",
            phase="EXPLOITATION",
            target="10.10.15.65",
            test_command='@PJL FSDOWNLOAD NAME="x" SIZE=1',
            test_response="FILEERROR=1",
            verification_status="syntax_uncertain",
            rejection_reason="argument order needs source-verified re-test",
        )
    assert not path.exists(), "invalid rejection must not mutate the board"


def test_hypothesis_preserves_verified_rejection_details(tmp_path):
    path = tmp_path / "hypotheses.md"
    record = hypotheses.update_hypothesis(
        path,
        in_scope_hosts={"10.10.15.65"},
        id="001",
        title="PJL file download",
        status="Rejected",
        phase="EXPLOITATION",
        target="10.10.15.65",
        test_command='@PJL FSDOWNLOAD NAME="x" SIZE=1',
        test_response="parser branch proves feature disabled",
        verification_status="not_implemented",
        rejection_reason="source-verified stub",
    )

    assert record.verification_status == "not_implemented"
    text = path.read_text(encoding="utf-8")
    assert '- **Test Command:** @PJL FSDOWNLOAD NAME="x" SIZE=1' in text
    assert "- **Verification Status:** not_implemented" in text
    assert "- **Rejection Reason:** source-verified stub" in text


def test_hypothesis_write_accepts_descriptive_target_context(tmp_path):
    record = hypotheses.update_hypothesis(
        tmp_path / "hypotheses.md",
        in_scope_hosts={"cctv.htb"},
        id="001",
        title="Camera portal",
        status="Candidate",
        phase="VULN_RESEARCH",
        target="cctv.htb (/zm/index.php, camera portal)",
    )
    assert record.target == "cctv.htb (/zm/index.php, camera portal)"
