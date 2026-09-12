"""Unit tests for structured and unstructured HTTP observation parsing."""

from __future__ import annotations

from plugins.violin_guard.core.http_observations import parse_http_statuses


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
