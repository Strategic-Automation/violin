"""Contract tests for the machine-readable HTTP evidence parser.

The parser feeds decisive-proof decisions, so it has to read exactly the forms
the guard recommends (`-i` captures carry a status line *and* headers) and
nothing else. Response header values are the interesting false-positive class:
`Content-Length: 200` and `Retry-After: 429` are metadata, not observed
statuses.
"""

from __future__ import annotations

from plugins.violin_guard.core.evidence.http_observations import (
    parse_http_observations,
    parse_http_statuses,
)


def test_header_lines_are_not_read_as_statuses() -> None:
    body = (
        "HTTP/1.1 403 Forbidden\r\n"
        "Content-Length: 200\r\n"
        "Retry-After: 429\r\n"
        "Content-Type: application/json\r\n"
    )

    assert parse_http_statuses(body) == (403,)


def test_header_values_do_not_satisfy_a_positive_result() -> None:
    # A rejected request whose headers happen to carry 2xx/3xx numbers must not
    # look like an accepted one.
    body = "HTTP/1.1 401 Unauthorized\nContent-Length: 201\nLocation: 302\n"

    assert parse_http_statuses(body) == (401,)


def test_status_line_and_curl_write_out_forms_still_parse() -> None:
    assert parse_http_statuses("HTTP/1.1 200 OK\n") == (200,)
    assert parse_http_statuses("[201]\n") == (201,)
    assert parse_http_statuses("HTTPCODE:404\n") == (404,)


def test_labeled_and_bare_burst_forms_still_parse() -> None:
    # `-w "req $i %{http_code}\n"` and `-w '%{http_code} '` burst output.
    assert parse_http_statuses("req 1 401\n") == (401,)
    assert parse_http_statuses("401 401 401\n") == (401, 401, 401)


def test_statuses_dict_form_still_expands_repetition_counts() -> None:
    assert parse_http_statuses("burst statuses: {401: 9, 429: 1}\n") == (
        *([401] * 9),
        429,
    )


def test_structured_observations_are_read_from_jsonl_only() -> None:
    body = (
        '{"type":"http_observation","flow_id":"flow-a","method":"GET","url":"https://a.test/x",'
        '"status":200}\n'
        "GET https://a.test/x HTTP/1.1 200\n"
        '{"type":"other","method":"GET","url":"https://a.test/x","status":500}\n'
    )

    observations = parse_http_observations(body)

    assert [(value.method, str(value.url), value.status) for value in observations] == [
        ("GET", "https://a.test/x", 200)
    ]
    assert parse_http_statuses(body) == (200, 200)


def test_structured_observations_allow_legacy_ids_and_reject_reused_explicit_ids() -> None:
    missing_id = '{"type":"http_observation","method":"GET","url":"https://a.test/x","status":200}'
    duplicate_id = (
        '{"type":"http_observation","flow_id":"same","method":"GET","url":"https://a.test/x","status":200}\n'
        '{"type":"http_observation","flow_id":"same","method":"GET","url":"https://a.test/y","status":200}'
    )
    assert len(parse_http_observations(missing_id)) == 1
    assert parse_http_observations(duplicate_id) == ()


def test_parse_http_statuses_formats() -> None:
    # Standard status line
    assert parse_http_statuses("HTTP/1.1 200 OK\n") == (200,)
    assert parse_http_statuses("HTTP 404 Not Found\n") == (404,)

    # Bracket form
    assert parse_http_statuses("[200]\n") == (200,)

    # HTTPCODE form
    assert parse_http_statuses("HTTPCODE:502\n") == (502,)

    # Status followed by body
    assert parse_http_statuses('200 {"user": "alice"}\n') == (200,)
    assert parse_http_statuses("200 [1, 2, 3]\n") == (200,)
    assert parse_http_statuses("404 <html\n") == (404,)

    # Scripted tuple forms (labeled and bare)
    assert parse_http_statuses('(200, \'{"user": "alice"}\')\n') == (200,)
    assert parse_http_statuses("LABEL (401, 'unauthorized')\n") == (401,)
    assert parse_http_statuses("(404, '')\n") == (404,)

    # Non-HTTP numeric lines should NOT be parsed as HTTP status codes
    assert parse_http_statuses("500 items found in the database\n") == ()
    assert parse_http_statuses("200 files scanned successfully\n") == ()
    assert parse_http_statuses("404 users updated\n") == ()
