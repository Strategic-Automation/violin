"""Tests for automatic HTTP status-line capture in evidence-producing probes."""

from plugins.violin_guard.core.commands.http_proof import normalize_http_proof_flags


def test_injects_i_into_plain_curl_get():
    cmd = "curl -sS --max-time 30 https://duck-store.escape.tech/api/v1/users/"
    out = normalize_http_proof_flags(cmd)
    assert out.startswith("curl -i")
    assert "-i" in out


def test_injects_i_into_curl_with_data():
    cmd = "curl -sS -X POST -H 'Content-Type: application/json' -d '{}' https://duck-store.escape.tech/api/v1/auth/login"
    out = normalize_http_proof_flags(cmd)
    assert "-i" in out
    assert "-H 'Content-Type: application/json' -d '{}'" in out


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


def test_adds_status_capture_to_redirected_body():
    cmd = "curl -sS --max-time 30 https://duck-store.escape.tech/ > /tmp/out.txt"
    assert normalize_http_proof_flags(cmd).startswith("curl -i -sS")


def test_injects_status_to_stdout_when_curl_writes_body_file():
    cmd = "curl -sS -o body.json https://duck-store.escape.tech/api/v1/users/ && python3 parse.py body.json"
    out = normalize_http_proof_flags(cmd)
    assert "-w 'HTTP %{http_code}\\n'" in out
    assert "curl -i" not in out
    assert out.endswith("&& python3 parse.py body.json")


def test_injects_status_for_long_output_flag():
    cmd = "curl --output=body.json -sS https://duck-store.escape.tech/api/v1/users/"
    assert "-w 'HTTP %{http_code}\\n'" in normalize_http_proof_flags(cmd)


def test_injects_i_for_wget_too():
    cmd = "wget -q https://duck-store.escape.tech/robots.txt"
    out = normalize_http_proof_flags(cmd)
    assert "wget -S" in out


def test_leaves_piped_probe_stdout_untouched():
    """A probe whose stdout feeds a parser must not be reshaped.

    Injecting ``-i`` ahead of a JSON consumer makes it fail to decode the body
    and the probe silently degrades to an unauthenticated request.
    """
    cmd = (
        "curl -sS -X POST https://duck-store.escape.tech/api/v1/auth/login "
        "-H 'Content-Type: application/json' -d '{}' "
        "| python3 -c 'import json,sys; print(json.load(sys.stdin)[\"access_token\"])'"
    )
    assert normalize_http_proof_flags(cmd) == cmd


def test_leaves_piped_probe_untouched_after_stderr_redirect():
    cmd = "curl -sS https://duck-store.escape.tech/api/v1/users/ 2>/dev/null | jq -r '.id'"
    assert normalize_http_proof_flags(cmd) == cmd


def test_leaves_piped_probe_untouched_after_stream_merge():
    cmd = "curl -sS https://duck-store.escape.tech/api/v1/orders/1 2>&1 | grep -o 'total'"
    assert normalize_http_proof_flags(cmd) == cmd


def test_injects_i_for_logical_or_operator():
    """``||`` is not a pipe: no consumer parses this probe's stdout."""
    cmd = "curl -sS https://duck-store.escape.tech/api/v1/users/ || echo unavailable"
    assert normalize_http_proof_flags(cmd).startswith("curl -i")


def test_leaves_xargs_wrapped_probe_untouched():
    """Capture is injected only into a direct curl/wget invocation.

    A probe wrapped inside another program's arguments (``xargs``, ``parallel``)
    is left byte-identical: the rewriter never edits text it does not own.
    """
    cmd = "cat ids.txt | xargs -I{} curl -sS https://duck-store.escape.tech/api/v1/orders/{}"
    assert normalize_http_proof_flags(cmd) == cmd


def test_injects_status_for_probe_followed_by_logical_and():
    """The response file remains a body, while stdout records the status."""
    cmd = "curl -sS -o body.txt https://duck-store.escape.tech/ && wc -c body.txt"
    out = normalize_http_proof_flags(cmd)
    assert "-w 'HTTP %{http_code}\\n'" in out
    assert "curl -i" not in out


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
    assert "wget -S -q" in out


def test_leaves_probe_captured_into_a_variable_untouched():
    """TOKEN=$(curl ...) consumes stdout, so -i would corrupt the captured body."""
    cmd = "TOKEN=$(curl -s https://duck-store.escape.tech/api/v1/auth/login)"
    assert normalize_http_proof_flags(cmd) == cmd


def test_leaves_backtick_probe_captured_into_a_variable_untouched():
    cmd = "TOKEN=`curl -s https://duck-store.escape.tech/api/v1/auth/login`"
    assert normalize_http_proof_flags(cmd) == cmd


def test_still_injects_when_stdout_reaches_the_receipt():
    cmd = "curl -s https://duck-store.escape.tech/api/v1/health; echo done"
    assert "-i" in normalize_http_proof_flags(cmd)
