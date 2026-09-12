"""HTTP proof-capture helpers shared by command gates and the execution engine.

A target probe's saved evidence is only interpretable later (for scoring,
reporting, or replay) if it records a literal ``HTTP/1.x <code>`` status line.
Plain ``curl -s`` prints only the body and discards the status/headers. This
module provides a pure rewriter that injects ``-i`` for curl or ``-S`` for wget
when an HTTP probe lacks a status-capture flag. It lives here (lower-level than
both gates and engine) so either layer can apply it without a circular import.
"""

from __future__ import annotations

import re
import shlex

from .bash_ast import parse_bash_segments

_HTTP_URL_RE = re.compile(r"https?://\S+", re.I)

_CLIENT_TOKEN_RE = {
    "curl": re.compile(r"(?<!\S)(?:[^\s;&|()]+[\\/])?curl(?:\.exe)?(?=\s|$)", re.I),
    "wget": re.compile(r"(?<!\S)(?:[^\s;&|()]+[\\/])?wget(?:\.exe)?(?=\s|$)", re.I),
}
_CAPTURE_LONG_FLAGS = {
    "curl": frozenset({"--include", "--verbose", "--head", "--dump-header", "--write-out"}),
    "wget": frozenset({"--server-response"}),
}

# Flags that already cause a status/header line to be captured (curl:
# -i/--include, -I/--head, -D/--dump-header, -w/--write-out; -v/--verbose
# includes headers. wget: -S/--server-response).
_CAPTURE_SHORT_FLAGS = {"curl": "ivIDw", "wget": "S"}
_INJECTED_CAPTURE_FLAG = {"curl": "-i", "wget": "-S"}


def has_capture_flag(command: str, client: str) -> bool:
    """Return whether one curl/wget command already records response status."""
    try:
        tokens = shlex.split(command, posix=True)
    except ValueError:
        tokens = command.split()
    long_flags = _CAPTURE_LONG_FLAGS[client]
    short_flags = set(_CAPTURE_SHORT_FLAGS[client])
    for token in tokens:
        if token in long_flags or any(token.startswith(f"{flag}=") for flag in long_flags):
            return True
        if re.fullmatch(r"-[A-Za-z]+", token) and any(
            character in short_flags for character in token[1:]
        ):
            return True
    return False


def normalize_http_proof_flags(command: str) -> str:
    """Inject the client-specific flag into an HTTP probe missing status capture.

    Returns the original command unchanged unless it is an HTTP probe to an
    http(s) URL using curl/wget with no status-capture flag, in which case
    the flag is inserted immediately after the client token without rebuilding
    or re-quoting the rest of the command.
    """
    insertions: list[tuple[int, str]] = []
    search_start = 0
    for segment in parse_bash_segments(command):
        client = segment.executable.casefold().removesuffix(".exe")
        if client not in _CLIENT_TOKEN_RE or not _HTTP_URL_RE.search(segment.raw_text):
            continue
        if has_capture_flag(segment.raw_text, client):
            continue
        segment_start = command.find(segment.raw_text, search_start)
        if segment_start < 0:
            continue
        client_match = _CLIENT_TOKEN_RE[client].search(segment.raw_text)
        if client_match is None:
            continue
        insertions.append(
            (segment_start + client_match.end(), f" {_INJECTED_CAPTURE_FLAG[client]}")
        )
        search_start = segment_start + len(segment.raw_text)

    rewritten = command
    for position, value in reversed(insertions):
        rewritten = rewritten[:position] + value + rewritten[position:]
    return rewritten


__all__ = [
    "has_capture_flag",
    "normalize_http_proof_flags",
]
