"""Tests for the record-as-you-go recency gate (deferred bookkeeping blocker)."""

from __future__ import annotations

import os
import time
from pathlib import Path

from plugins.violin_guard.gates import command
from plugins.violin_guard.gates.command import Phase

_STALE_HYP = """### H-001: Queue service validation
- **Target:** 10.129.47.140:1515
- **Status:** Validated
- **Phase:** EXPLOITATION
- **CVE Research:** web_search queue 1515 CVE; NVD; no results
- **Exploit Research:** web_search queue 1515 exploit; GitHub; no results
- **Updated:** 2026-08-01 10:00
"""

_FRESH_HYP = """### H-001: Queue service validation
- **Target:** 10.129.47.140:1515
- **Status:** Validated
- **Phase:** EXPLOITATION
- **CVE Research:** web_search queue 1515 CVE; NVD; no results
- **Exploit Research:** web_search queue 1515 exploit; GitHub; no results
- **Updated:** {updated}
"""


def _make_engagement(tmp_path: Path, hyp_text: str, evidence_age: float) -> Path:
    eng = tmp_path / "eng"
    eng.mkdir(parents=True, exist_ok=True)
    (eng / "hypotheses.md").write_text(hyp_text, encoding="utf-8")
    exec_dir = eng / "evidence" / "executions"
    exec_dir.mkdir(parents=True)
    receipt = exec_dir / "2026-08-10T120000-deadbeef-exec.json"
    receipt.write_text('{"command": "test"}', encoding="utf-8")
    # age the evidence file: now - evidence_age seconds
    stamp = time.time() - evidence_age
    os.utime(receipt, (stamp, stamp))
    return eng


def test_recency_gate_hints_during_exploitation(tmp_path: Path) -> None:
    """Evidence 2h old, board updated a month ago -> hint (warning), not a block."""
    eng = _make_engagement(tmp_path, _STALE_HYP, evidence_age=2 * 3600)
    result = command.check_hypothesis_freshness(
        eng, Phase.EXPLOITATION, "python3 exploit.py 10.129.47.140 1515"
    )
    assert not result.errors  # must not hard-block mid-exploitation
    assert any("predates the latest execution" in w for w in result.warnings)
    assert "hint, not a block" in " ".join(result.warnings)
    assert result.exit_code() == 0  # advisory hints must not escalate exit code


def test_recency_gate_passes_when_board_fresh(tmp_path: Path) -> None:
    """Board updated after the latest evidence -> gate silent."""
    now = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime())
    eng = _make_engagement(tmp_path, _FRESH_HYP.format(updated=now), evidence_age=60)
    result = command.check_hypothesis_freshness(
        eng, Phase.EXPLOITATION, "python3 exploit.py 10.129.47.140 1515"
    )
    assert not any("not been updated since" in err for err in result.errors)


def test_recency_gate_grace_window(tmp_path: Path) -> None:
    """Evidence slightly newer than board (within grace) must not block."""
    # board updated 5 min ago, evidence 10 min ago -> evidence is OLDER
    now = time.time()
    updated_str = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(now - 300))
    eng = _make_engagement(tmp_path, _FRESH_HYP.format(updated=updated_str), evidence_age=600)
    result = command.check_hypothesis_freshness(
        eng, Phase.EXPLOITATION, "python3 exploit.py 10.129.47.140 1515"
    )
    assert not any("not been updated since" in err for err in result.errors)


def test_recency_gate_noop_without_evidence(tmp_path: Path) -> None:
    """No execution evidence -> gate never fires (recon/early phases)."""
    eng = tmp_path / "eng"
    eng.mkdir(parents=True, exist_ok=True)
    (eng / "hypotheses.md").write_text(_STALE_HYP, encoding="utf-8")
    result = command.check_hypothesis_freshness(
        eng, Phase.EXPLOITATION, "python3 exploit.py 10.129.47.140 1515"
    )
    assert not any("not been updated since" in err for err in result.errors)


def test_recency_gate_recon_phases_untouched(tmp_path: Path) -> None:
    """Recon does not require hypotheses at all — gate must stay silent."""
    eng = _make_engagement(tmp_path, _STALE_HYP, evidence_age=2 * 3600)
    result = command.check_hypothesis_freshness(eng, Phase.RECON, "nmap -p- 10.129.47.140")
    assert not result.errors


def test_recency_gate_suppressed_during_burst(tmp_path: Path) -> None:
    """During burst execution, recency hints must be suppressed."""
    eng = _make_engagement(tmp_path, _STALE_HYP, evidence_age=2 * 3600)
    result = command.check_hypothesis_freshness(
        eng,
        Phase.EXPLOITATION,
        "python3 exploit.py 10.129.47.140 1515",
        is_burst=True,
    )
    assert not result.errors
    assert not any("predates the latest execution" in w for w in result.warnings)


def test_recency_gate_suppressed_when_batch_in_progress(tmp_path: Path) -> None:
    """When a bounded batch is in progress, recency hints must be suppressed."""
    from plugins.violin_guard.core import state

    eng = _make_engagement(tmp_path, _STALE_HYP, evidence_age=2 * 3600)
    # Simulate an active pending sync batch
    state.mark_pending_sync(eng, "curl http://10.129.47.140/probe", "exploitation", "PT-103")
    result = command.check_hypothesis_freshness(
        eng,
        Phase.EXPLOITATION,
        "python3 exploit.py 10.129.47.140 1515",
    )
    assert not result.errors
    assert not any("predates the latest execution" in w for w in result.warnings)


def test_operational_task_in_exploitation_hypothesis_optional(tmp_path: Path) -> None:
    """PT-103/PT-104 operational checks (e.g. CORS/rate-limiting) do not require hypotheses."""
    eng = tmp_path / "eng"
    eng.mkdir(parents=True, exist_ok=True)
    # Empty hypothesis board
    (eng / "hypotheses.md").write_text("# Hypotheses\n", encoding="utf-8")

    # Under PT-103 in EXPLOITATION, check passes without error
    result = command.check_hypothesis_freshness(
        eng,
        Phase.EXPLOITATION,
        "curl -i http://10.129.47.140:1515/api/cors-test",
        primary_target="10.129.47.140:1515",
        task_id="PT-103",
    )
    assert not result.errors
    assert any("operational check" in info for info in result.infos)

    # Under PT-104 in EXPLOITATION, check also passes without error
    result_pt104 = command.check_hypothesis_freshness(
        eng,
        Phase.EXPLOITATION,
        "curl -i http://10.129.47.140:1515/api/rate-limit-test",
        primary_target="10.129.47.140:1515",
        task_id="PT-104",
    )
    assert not result_pt104.errors
    assert any("operational check" in info for info in result_pt104.infos)


def test_non_operational_task_in_exploitation_requires_hypothesis(tmp_path: Path) -> None:
    """Non-operational tasks (e.g. PT-102) in EXPLOITATION still require valid hypotheses."""
    eng = tmp_path / "eng"
    eng.mkdir(parents=True, exist_ok=True)
    (eng / "hypotheses.md").write_text("# Hypotheses\n", encoding="utf-8")

    result = command.check_hypothesis_freshness(
        eng,
        Phase.EXPLOITATION,
        "curl -i http://10.129.47.140:1515/api/exploit",
        primary_target="10.129.47.140:1515",
        task_id="PT-102",
    )
    assert result.errors
    assert any("requires at least one hypothesis" in err for err in result.errors)
