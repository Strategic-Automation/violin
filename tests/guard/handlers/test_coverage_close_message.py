"""Coverage-close errors must stay actionable and bounded in size.

A gate message is prompt text: every failed close attempt costs tokens in the
agent's context. Listing every undispositioned obligation verbatim produced a
single multi-hundred-word line, so the message enumerates a bounded sample and
summarises the remainder.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from plugins.violin_guard.core.engagement import bootstrap
from plugins.violin_guard.handlers.ptt_gates import _validate_phase_exit

OBLIGATIONS = (
    "GET /api/v1/auth/login",
    "POST /api/v1/auth/login",
    "GET /api/v1/cart",
    "POST /api/v1/cart/items",
    "GET /api/v1/orders",
    "POST /api/v1/orders/checkout",
)


def _engagement(tmp_path: Path) -> Path:
    engagement = tmp_path / "engagement"
    assert bootstrap.init_engagement(engagement, host="10.10.10.10") == 0
    scope = engagement / "scope" / "scope.yaml"
    obligations = "".join(f"    - {item}\n" for item in OBLIGATIONS)
    scope.write_text(
        scope.read_text(encoding="utf-8")
        + "\nengagement:\n  audit_mode: true\n  coverage_obligations:\n"
        + obligations,
        encoding="utf-8",
    )
    matrix = engagement / "state" / "coverage-matrix.yaml"
    matrix.write_text(
        "coverage:\n  rate_limits:\n    status: tested\n"
        "    evidence_or_reason: 'evidence/recon/probe.txt'\n",
        encoding="utf-8",
    )
    return engagement


def test_coverage_close_error_bounds_enumerated_obligations(tmp_path: Path) -> None:
    engagement = _engagement(tmp_path)
    with pytest.raises(ValueError) as failure:
        _validate_phase_exit(engagement, "PT-030", "[x]")

    message = str(failure.value)
    assert "no coverage-matrix cell" in message
    assert message.count("(no coverage-matrix cell)") <= 3, message
    assert re.search(r"\+\d+ more", message), message


def test_coverage_close_error_stays_within_token_budget(tmp_path: Path) -> None:
    engagement = _engagement(tmp_path)
    with pytest.raises(ValueError) as failure:
        _validate_phase_exit(engagement, "PT-030", "[x]")

    message = str(failure.value)
    assert len(message) <= 900, len(message)
    for obligation in OBLIGATIONS[3:]:
        assert obligation not in message, obligation


def test_coverage_close_error_keeps_the_exact_key_rule(tmp_path: Path) -> None:
    engagement = _engagement(tmp_path)
    with pytest.raises(ValueError) as failure:
        _validate_phase_exit(engagement, "PT-030", "[x]")

    message = str(failure.value)
    assert "EXACT lowercased obligation strings" in message
    assert "First missing:" in message
