"""test_benchmark_runner.py — Unit tests for benchmark runner and score exports."""

from pathlib import Path

from benchmark.run import init_benchmark_engagement
from benchmark.score import (
    generate_markdown_summary,
    has_proof,
    score_engagement,
)

CALIBRATION_DIR = (
    Path(__file__).resolve().parent.parent.parent
    / "benchmark"
    / "targets"
    / "duck-store"
    / "calibration"
)


def test_init_benchmark_engagement(tmp_path: Path) -> None:
    eng_dir = tmp_path / "eng"
    target = "http://test-target.local:8080"
    init_benchmark_engagement(eng_dir, target)

    assert (eng_dir / "scope" / "scope.yaml").exists()
    assert (eng_dir / "state" / "ptt.md").exists()
    assert (eng_dir / "hypotheses.md").exists()
    assert (eng_dir / "state" / "history.md").exists()

    scope_text = (eng_dir / "scope" / "scope.yaml").read_text(encoding="utf-8")
    assert target in scope_text


def test_generate_markdown_summary() -> None:
    dummy_result = {
        "ptt": {"done": 3, "total": 3},
        "hyp_created": 5,
        "hyp_resolved": 4,
        "hist_lines": 12,
        "hist_blocks": 0,
        "ev_count": 4,
        "total": 20,
        "confirmed": 16,
        "touched": 2,
        "not_tested": 2,
        "confirmed_details": [{"id": "sqli-01", "files": ["evidence/sqli.txt"]}],
        "touched_details": [],
        "missed_details": [{"id": "xss-01", "reason": "no evidence"}],
        "violations": 0,
        "compliance_unknown": False,
    }

    md = generate_markdown_summary(dummy_result)
    assert "Hermes Profile Benchmark" in md
    assert "16/20 (80%)" in md
    assert "sqli-01" in md
    assert "xss-01" in md
    assert "COMPLIANT" in md


def test_calibration_known_good() -> None:
    """Score the known-good calibration fixture — expects exactly 14 confirmed."""
    known_good = CALIBRATION_DIR / "known-good"
    assert known_good.exists(), f"Calibration fixture missing: {known_good}"

    result = score_engagement(known_good)
    assert result["confirmed"] == 14, (
        f"known-good should confirm 14 challenges, got {result['confirmed']}"
    )
    assert result["violations"] == 0


def test_calibration_known_bad() -> None:
    """Score the known-bad calibration fixture — expects exactly 0 confirmed."""
    known_bad = CALIBRATION_DIR / "known-bad"
    assert known_bad.exists(), f"Calibration fixture missing: {known_bad}"

    result = score_engagement(known_bad)
    assert result["confirmed"] == 0, (
        f"known-bad should confirm 0 challenges, got {result['confirmed']}"
    )


def test_calibration_known_good_no_false_negatives_in_confirmed() -> None:
    """Verify all 14 confirmed challenges are the expected critical+high ones."""
    known_good = CALIBRATION_DIR / "known-good"
    result = score_engagement(known_good)
    confirmed_ids = {d["id"] for d in result["confirmed_details"]}

    expected_ids = {
        "weak-admin-creds",
        "jwt-alg-none",
        "totp-bypass",
        "idor-user-profiles",
        "mass-assign-role",
        "coupon-100-discount",
        "referral-abuse",
        "sqli-color-filter",
        "xss-testimonials",
        "ssrf-image-import",
        "ssrf-fetch-url",
        "unauth-testimonial-mod",
        "idor-order-details",
        "bac-admin-users",
    }
    assert confirmed_ids == expected_ids, (
        f"Mismatch: extra={confirmed_ids - expected_ids}, missing={expected_ids - confirmed_ids}"
    )


def test_auto_judge_unblinded_hypothesis_matching(tmp_path: Path) -> None:
    """Verify that unblinded hypotheses without explicit Linked challenges tag auto-match via evidence."""
    eng_dir = tmp_path / "eng_unblinded"
    init_benchmark_engagement(eng_dir, "https://duck-store.escape.tech")

    ev_dir = eng_dir / "evidence" / "executions"
    ev_dir.mkdir(parents=True, exist_ok=True)
    ev_file = ev_dir / "2026-08-06T000000-sqli-test.stdout.txt"
    ev_file.write_text(
        "GET /api/v1/products/filter/by-color?color=red SQL error PostgresSyntaxError HTTP/1.1 200 OK"
    )

    hyp_md = eng_dir / "hypotheses.md"
    hyp_md.write_text("""# Hypothesis Board
### H-002: SQL Injection in Product Filter
**Status:** Validated
**Linked findings:** FIND-001
**Runtime Evidence:** evidence/executions/2026-08-06T000000-sqli-test.stdout.txt
""")

    result = score_engagement(eng_dir)
    confirmed_ids = {d["id"] for d in result["confirmed_details"]}
    assert "sqli-color-filter" in confirmed_ids, (
        f"Expected sqli-color-filter auto-confirmed, got {confirmed_ids}"
    )


def test_has_proof_json_validation(tmp_path: Path) -> None:
    """Verify that has_proof requires valid, non-empty JSON structures."""
    f1 = tmp_path / "valid_dict.json"
    f1.write_text('{"id": "123", "status": "completed_success"}', encoding="utf-8")
    assert has_proof(f1) is True

    f2 = tmp_path / "valid_list.json"
    f2.write_text('[{"item": "val", "detail": "response payload"}]', encoding="utf-8")
    assert has_proof(f2) is True

    f3 = tmp_path / "empty_dict.json"
    f3.write_text("{}", encoding="utf-8")
    assert has_proof(f3) is False

    f4 = tmp_path / "empty_list.json"
    f4.write_text("[]", encoding="utf-8")
    assert has_proof(f4) is False
