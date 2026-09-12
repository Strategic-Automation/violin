"""Unified redaction utilities for credentials, tokens, and sensitive material."""

from __future__ import annotations

import re

REDACTED = "[REDACTED]"
REDACTED_JWT = "[REDACTED_JWT]"
REDACTED_TOKEN = "[REDACTED_TOKEN]"
REDACTED_API_KEY = "[REDACTED_API_KEY]"
REDACTED_PRIVATE_KEY = "[REDACTED_PRIVATE_KEY]"

SENSITIVE_FIELD_KEYS = frozenset(
    {
        "access_token",
        "api_key",
        "apikey",
        "authorization",
        "cookie",
        "passwd",
        "password",
        "private_key",
        "refresh_token",
        "secret",
        "set_cookie",
        "token",
    }
)

PRIVATE_KEY_RE = re.compile(
    r"-----BEGIN (?P<label>(?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?)-----.*?"
    r"(?:-----END (?P=label)-----|\Z)",
    re.IGNORECASE | re.DOTALL,
)

AUTHORIZATION_RE = re.compile(
    r"(?i)([\"']?\bauthorization\b[\"']?\s*[:=]\s*)(?!\s*bearer\b)"
    r"(?:\"(?:\\.|[^\"\\])*\"|'(?:\\.|[^'\\])*'|[^\r\n,;}]+)"
)

COOKIE_RE = re.compile(
    r"(?im)([\"']?\b(?:set[-_]?cookie|cookie)\b[\"']?\s*[:=]\s*)"
    r"(?:\"(?:\\.|[^\"\\])*\"|'(?:\\.|[^'\\])*'|[^\r\n,}]+)"
)

SECRET_ASSIGNMENT_RE = re.compile(
    r"(?i)([\"']?\b(?:password|passwd|secret|token|access[_-]?token|refresh[_-]?token|"
    r"api[_-]?key|apikey|private[_-]?key)\b[\"']?\s*[:=]\s*)"
    r"(?:\"(?:\\.|[^\"\\])*\"|'(?:\\.|[^'\\])*'|[^\s,;}\]]+)"
)

BEARER_TOKEN_RE = re.compile(r"(?i)\bbearer[ \t]+[A-Za-z0-9._~+/=-]{8,}")

JWT_RE = re.compile(
    r"(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\."
    r"[A-Za-z0-9_-]{5,}(?![A-Za-z0-9_-])"
)

PROVIDER_TOKEN_RE = re.compile(
    r"(?<![A-Za-z0-9_-])(?:sk-or-v1-[A-Za-z0-9_-]{16,}|sk-[A-Za-z0-9_-]{16,}|"
    r"gh[pousr]_[A-Za-z0-9]{20,}|xox[baprs]-[A-Za-z0-9-]{10,})(?![A-Za-z0-9_-])"
)


def redact_text(value: str) -> str:
    """Perform comprehensive multi-pass secret redaction on arbitrary text."""
    if not value:
        return value
    redacted = PRIVATE_KEY_RE.sub(REDACTED_PRIVATE_KEY, value)
    redacted = BEARER_TOKEN_RE.sub(f"Bearer {REDACTED_TOKEN}", redacted)
    redacted = COOKIE_RE.sub(lambda match: f"{match.group(1)}{REDACTED}", redacted)
    redacted = AUTHORIZATION_RE.sub(lambda match: f"{match.group(1)}{REDACTED}", redacted)
    redacted = SECRET_ASSIGNMENT_RE.sub(lambda match: f"{match.group(1)}{REDACTED}", redacted)
    redacted = JWT_RE.sub(REDACTED_JWT, redacted)
    return PROVIDER_TOKEN_RE.sub(REDACTED_TOKEN, redacted)


def redact_single_line(note: str) -> str:
    """Collapse note to a single line and redact credentials for tabular records."""
    one_line = " ".join(note.splitlines()).strip()
    redacted = PRIVATE_KEY_RE.sub(REDACTED_PRIVATE_KEY, one_line)
    redacted = BEARER_TOKEN_RE.sub(f"Bearer {REDACTED_TOKEN}", redacted)
    redacted = COOKIE_RE.sub(lambda match: f"{match.group(1)}{REDACTED}", redacted)
    redacted = AUTHORIZATION_RE.sub(lambda match: f"{match.group(1)}{REDACTED}", redacted)
    redacted = SECRET_ASSIGNMENT_RE.sub(lambda match: f"{match.group(1)}{REDACTED}", redacted)
    redacted = JWT_RE.sub(REDACTED_JWT, redacted)
    return PROVIDER_TOKEN_RE.sub(REDACTED_API_KEY, redacted)
