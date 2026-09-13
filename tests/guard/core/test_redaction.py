"""Unit tests for secret and credential redaction across state and records."""

from __future__ import annotations

from plugins.violin_guard.core.redaction import (
    REDACTED,
    REDACTED_JWT,
    REDACTED_PRIVATE_KEY,
    REDACTED_TOKEN,
    redact_single_line,
    redact_text,
)


def test_redact_private_key() -> None:
    sample = (
        "Host certificate:\n"
        "-----BEGIN RSA PRIVATE KEY-----\n"
        "MIIEowIBAAKCAQEA0Y1m\n"
        "-----END RSA PRIVATE KEY-----\n"
        "Done."
    )
    result = redact_text(sample)
    assert REDACTED_PRIVATE_KEY in result
    assert "MIIEowIBAAKCAQEA0Y1m" not in result


def test_redact_bearer_and_jwt() -> None:
    jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
    raw = f"Authorization: Bearer {jwt}"
    result = redact_text(raw)
    assert "Authorization:" in result
    assert REDACTED in result or REDACTED_JWT in result or REDACTED_TOKEN in result
    assert jwt not in result


def test_redact_single_line_masks_passwords_and_cookies() -> None:
    multiline_note = (
        "Discovered administrative portal at /admin\n"
        'Tested login with password="admin_secret_123!"\n'
        "Received cookie: session_id=deadbeef9876543210;\n"
    )
    single_line = redact_single_line(multiline_note)

    assert "\n" not in single_line
    assert "admin_secret_123!" not in single_line
    assert "deadbeef9876543210" not in single_line
    assert REDACTED in single_line
    assert "Discovered administrative portal" in single_line


def test_redact_single_line_masks_authorization_and_provider_keys() -> None:
    note = (
        "curl -H 'Authorization: Basic dXNlcjpwYXNz' -H 'X-Api-Key: sk-ant-api03-abcdef1234567890'"
    )
    result = redact_single_line(note)
    assert "dXNlcjpwYXNz" not in result
    assert "sk-ant-api03-abcdef1234567890" not in result
    assert REDACTED in result or REDACTED_TOKEN in result
