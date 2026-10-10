"""Coverage identity is independent of disposition prose."""

from plugins.violin_guard.core.engagement.disposition_policy import evaluate_dispositions


def test_overlapping_routes_require_distinct_dispositions():
    obligations = [
        "POST /example/login",
        "POST /example/login/totp",
        "GET /example/users/",
        "GET /example/users/{uuid}",
    ]
    entries = {
        route: {"status": "tested", "evidence_or_reason": "evidence/recon/probe.txt"}
        for route in obligations[1::2]
    }
    result = evaluate_dispositions(entries, obligations=obligations)
    assert result.completed == 2
    assert result.total == 4
    assert result.missing_obligations == tuple(route.lower() for route in obligations[::2])
    assert not result.complete


def test_evidence_prose_cannot_establish_coverage_identity():
    result = evaluate_dispositions(
        {"login": {"status": "tested", "evidence_or_reason": "evidence/login.txt POST /login"}},
        obligations=["POST /login"],
    )
    assert result.completed == 0
    assert result.missing_obligations == ("post /login",)
    assert result.unrecognized_entries


def test_exact_keys_normalize_case_and_outer_whitespace():
    result = evaluate_dispositions(
        {"  POST /login  ": {"status": "tested", "evidence_or_reason": "evidence/login.txt"}},
        obligations=["post /login"],
    )
    assert result.complete
