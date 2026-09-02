"""Tests for automatic HTTP status-line capture in evidence-producing probes."""

from plugins.violin_guard.core.http_proof import normalize_http_proof_flags


def test_injects_i_into_plain_curl_get():
    cmd = "curl -sS --max-time 30 https://duck-store.escape.tech/api/v1/users/"
    out = normalize_http_proof_flags(cmd)
    assert out.startswith("curl -i")
    assert "-i" in out


def test_injects_i_into_curl_with_data():
    cmd = "curl -sS -X POST -H 'Content-Type: application/json' -d '{}' https://duck-store.escape.tech/api/v1/auth/login"
    out = normalize_http_proof_flags(cmd)
    assert "-i" in out


def test_injects_i_once_only():
    cmd = "curl -sS https://duck-store.escape.tech/api/v1/products/filter/by-color?color=Black"
    out = normalize_http_proof_flags(cmd)
    assert out.count("-i") == 1


def test_leaves_command_with_i_untouched():
    cmd = "curl -sS -i https://duck-store.escape.tech/api/v1/users/"
    assert normalize_http_proof_flags(cmd) == cmd


def test_leaves_command_with_w_untouched():
    cmd = "curl -sS -w 'HTTP %{http_code}' https://duck-store.escape.tech/api/v1/users/"
    assert normalize_http_proof_flags(cmd) == cmd


def test_leaves_non_http_command_untouched():
    cmd = "dig +short duck-store.escape.tech A"
    assert normalize_http_proof_flags(cmd) == cmd


def test_leaves_none_curl_untouched():
    cmd = "python3 -c 'print(1)'"
    assert normalize_http_proof_flags(cmd) == cmd


def test_leaves_offline_capture_untouched():
    cmd = "curl -sS --max-time 30 https://duck-store.escape.tech/ > /tmp/out.txt"
    assert normalize_http_proof_flags(cmd) == cmd


def test_injects_i_for_wget_too():
    cmd = "wget -q https://duck-store.escape.tech/robots.txt"
    out = normalize_http_proof_flags(cmd)
    assert "wget -i" in out


def test_preserves_quoted_url_fragments():
    cmd = "curl -sS 'https://duck-store.escape.tech/path?redirect=https://evil.example'"
    out = normalize_http_proof_flags(cmd)
    assert "https://duck-store.escape.tech/path?redirect=https://evil.example" in out
    assert "-i" in out


def test_injects_i_into_every_client_in_compound_command():
    cmd = "curl -s https://duck-store.escape.tech/a; curl -s https://duck-store.escape.tech/b"
    out = normalize_http_proof_flags(cmd)
    assert out.count("-i ") == 2
    assert "curl -i -s https://duck-store.escape.tech/a" in out
    assert "curl -i -s https://duck-store.escape.tech/b" in out


def test_injects_i_into_mixed_clients_in_compound_command():
    cmd = "curl -s https://duck-store.escape.tech/a && wget -q https://duck-store.escape.tech/b"
    out = normalize_http_proof_flags(cmd)
    assert "curl -i -s" in out
    assert "wget -i -q" in out
