from __future__ import annotations

from plugins.violin_guard.gates import command
from tests.guard.integration.guard_fixture import (
    _fake_target_executor as _fake_target_executor,
)


def test_exploitation_hypothesis_match_accepts_manual_field_order(tmp_path):
    (tmp_path / "hypotheses.md").write_text(
        """# Hypothesis Board

## Active Theories

### H-001: Queue service validation
- **Target:** 10.129.47.140:1515
- **Port:** 1515
- **Evidence:** evidence/vuln-research/queue.txt
- **CVE Research:** web_search queue service 1515 CVE; NVD; no results
- **Exploit Research:** web_search queue service 1515 exploit; GitHub; no results
- **Status:** Validated
- **Phase:** EXPLOITATION
""",
        encoding="utf-8",
    )

    result = command.check_hypothesis_freshness(
        tmp_path, command.Phase.EXPLOITATION, "python3 exploit.py 10.129.47.140 1515"
    )
    assert not result.errors, result.errors


def test_hypothesis_enforces_scope_target_fallback(tmp_path):
    """Verify hypothesis guard checks scope target when command contains no target string."""
    (tmp_path / "scope").mkdir(parents=True, exist_ok=True)
    (tmp_path / "scope" / "scope.yaml").write_text(
        "targets:\n  ip_addresses:\n    - 10.129.47.140\n"
        "rules_of_engagement:\n  allowed_actions: [RECON, EXPLOITATION]\n"
        "engagement:\n  name: Test\n"
        "authorized_parties: [Tester]\n"
        "authorisation:\n  confirmed: true\n",
        encoding="utf-8",
    )
    # Hypothesis is for a DIFFERENT target host (192.168.1.1)
    (tmp_path / "hypotheses.md").write_text(
        "# Hypothesis Board\n\n## Active Theories\n\n"
        "### H-001: Other host\n"
        "- **Target:** 192.168.1.1\n"
        "- **Status:** Validated\n"
        "- **Phase:** EXPLOITATION\n"
        "- **CVE Research:** Done\n"
        "- **Exploit Research:** Done\n",
        encoding="utf-8",
    )

    # Command has no IP string, but scope target 10.129.47.140 should NOT match 192.168.1.1 hypothesis
    result = command.check_hypothesis_freshness(
        tmp_path, command.Phase.EXPLOITATION, "python3 exploit.py"
    )
    assert result.errors, "Expected error when hypothesis target doesn't match scope target"
    assert any(
        "requires a non-rejected hypothesis matching the command target" in err
        for err in result.errors
    )


def test_rejected_hypothesis_testable_when_explicitly_linked(tmp_path):
    """A Rejected hypothesis must remain testable when the agent explicitly
    links its hypothesis_id, so the cheapest-test that the VULN_RESEARCH
    close gate requires can actually run (reject-then-test deadlock fix)."""
    (tmp_path / "scope").mkdir(parents=True, exist_ok=True)
    (tmp_path / "scope" / "scope.yaml").write_text(
        "targets:\n  in_scope_urls: [https://duck-store.escape.tech]\n"
        "  ip_addresses: []\n"
        "rules_of_engagement:\n  allowed_actions: [RECON, VULN_RESEARCH]\n"
        "engagement:\n  name: Test\n"
        "authorized_parties: [Tester]\n"
        "authorisation:\n  confirmed: true\n",
        encoding="utf-8",
    )
    (tmp_path / "hypotheses.md").write_text(
        "# Hypothesis Board\n\n## Active Theories\n\n"
        "### H-001: Default creds login\n"
        "- **Target:** https://duck-store.escape.tech\n"
        "- **Status:** Rejected\n"
        "- **Phase:** VULN_RESEARCH\n",
        encoding="utf-8",
    )

    # Explicitly linked to H-001: the Rejected hypothesis must be eligible so
    # its cheapest test can run.
    result = command.check_hypothesis_freshness(
        tmp_path,
        command.Phase.VULN_RESEARCH,
        "curl -i https://duck-store.escape.tech/api/v1/auth/login",
        hypothesis_id="H-001",
    )
    assert not result.errors, f"Rejected-but-linked hypothesis should be testable: {result.errors}"


def test_unphased_hypothesis_defaults_to_current_phase_when_linked(tmp_path):
    """An unphased hypothesis explicitly linked during VULN_RESEARCH defaults
    to the current phase so it can be dispositioned (empty-phase deadlock fix)."""
    (tmp_path / "scope").mkdir(parents=True, exist_ok=True)
    (tmp_path / "scope" / "scope.yaml").write_text(
        "targets:\n  in_scope_urls: [https://duck-store.escape.tech]\n"
        "rules_of_engagement:\n  allowed_actions: [RECON, VULN_RESEARCH]\n"
        "engagement:\n  name: Test\n"
        "authorized_parties: [Tester]\n"
        "authorisation:\n  confirmed: true\n",
        encoding="utf-8",
    )
    (tmp_path / "hypotheses.md").write_text(
        "# Hypothesis Board\n\n## Active Theories\n\n"
        "### H-001: API surface\n"
        "- **Target:** https://duck-store.escape.tech\n"
        "- **Status:** Candidate\n"
        "- **Phase:**\n",  # empty phase
        encoding="utf-8",
    )

    result = command.check_hypothesis_freshness(
        tmp_path,
        command.Phase.VULN_RESEARCH,
        "curl -i https://duck-store.escape.tech/api/v1/products",
        hypothesis_id="H-001",
    )
    assert not result.errors, (
        f"Unphased-but-linked hypothesis should default to current phase: {result.errors}"
    )


def test_unphased_hypothesis_defaults_to_current_phase_unlinked(tmp_path):
    """A hypothesis recorded without an explicit phase is acceptable to the
    gate without needing to be explicitly linked: the empty phase defaults to
    the phase in effect at the gate (empty-phase deadlock fix, #176)."""
    (tmp_path / "scope").mkdir(parents=True, exist_ok=True)
    (tmp_path / "scope" / "scope.yaml").write_text(
        "targets:\n  in_scope_urls: [https://duck-store.escape.tech]\n"
        "rules_of_engagement:\n  allowed_actions: [RECON, VULN_RESEARCH]\n"
        "engagement:\n  name: Test\n"
        "authorized_parties: [Tester]\n"
        "authorisation:\n  confirmed: true\n",
        encoding="utf-8",
    )
    (tmp_path / "hypotheses.md").write_text(
        "# Hypothesis Board\n\n## Active Theories\n\n"
        "### H-001: API surface\n"
        "- **Target:** https://duck-store.escape.tech\n"
        "- **Status:** Candidate\n"
        "- **Phase:**\n",  # empty phase: recorded without a phase
        encoding="utf-8",
    )

    result = command.check_hypothesis_freshness(
        tmp_path,
        command.Phase.VULN_RESEARCH,
        "curl -i https://duck-store.escape.tech/api/v1/products",
    )
    assert not result.errors, (
        f"Unphased hypothesis should be admitted against the current phase: {result.errors}"
    )
