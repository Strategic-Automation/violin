"""HTTP proof-flag guard tests — decisiveness of curl receipts at scoring time.

Regression: benchmark-run-20260811_175611 wrote 194 receipts but only 6
carried HTTP/1.1 status lines (plain `curl -s` without `-i`), so the
decisive-proof scorer rejected most of them. SKILL.md §4 mandates `-i`/`-sv`;
this guard makes the requirement a review gate.
"""

from __future__ import annotations

from plugins.violin_guard.command import check_http_proof_flags


def test_plain_silent_curl_warns_review() -> None:
    result = check_http_proof_flags("curl -s https://duck-store.escape.tech/api/v1/products")
    assert result.errors == []
    assert len(result.warnings) == 1
    assert "-i" in result.warnings[0]
    assert result.exit_code() == 2  # review, not hard block


def test_curl_with_status_capture_is_clean() -> None:
    for command in (
        "curl -si https://duck-store.escape.tech/api/v1/products",
        "curl -i -X POST https://duck-store.escape.tech/api/v1/auth/login -d '{}'",
        "curl -sv https://duck-store.escape.tech/api/v1/orders/1",
        "curl -I https://duck-store.escape.tech/",
        "curl -D headers.txt https://duck-store.escape.tech/api/v1/products",
    ):
        result = check_http_proof_flags(command)
        assert result.errors == [] and result.warnings == [], command
        assert result.exit_code() == 0, command


def test_status_probe_and_offline_capture_exempt() -> None:
    for command in (
        "curl -s -o /dev/null -w '%{http_code}' https://duck-store.escape.tech/api/v1/auth/login",
        "curl -sO https://duck-store.escape.tech/bundle.js",
        "curl -s https://duck-store.escape.tech/api/v1/products > evidence/recon/products.json",
    ):
        result = check_http_proof_flags(command)
        assert result.errors == [] and result.warnings == [], command


def test_non_http_or_non_curl_commands_untouched() -> None:
    for command in (
        "nmap -sV 10.10.10.10",
        "grep -i admin evidence/recon/products.json",
        "python3 tools/burst.py --target https://duck-store.escape.tech",
    ):
        result = check_http_proof_flags(command)
        assert result.errors == [] and result.warnings == [], command
