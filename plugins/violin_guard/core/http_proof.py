"""HTTP proof-capture helpers shared by command gates and the execution engine.

A target probe's saved evidence is only interpretable later (for scoring,
reporting, or replay) if it records a response status. Plain ``curl -s``
prints only the body and discards the status/headers. This module provides a
pure rewriter that injects ``-i`` for curl, ``-w`` when curl
writes the response body to a separate file, or ``-S`` for wget when an HTTP
probe lacks status capture. It lives here (lower-level than both gates and
engine) so either layer can apply it without a circular import.
"""

from __future__ import annotations

import re
import shlex

from .bash_ast import CommandSegment, parse_bash_segments

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


def _segment_spans(command: str, segments: list[CommandSegment]) -> list[tuple[int, int] | None]:
    """Locate each parsed segment in the original command text, in order."""
    spans: list[tuple[int, int] | None] = []
    search_start = 0
    for segment in segments:
        start = command.find(segment.raw_text, search_start)
        if start < 0:
            spans.append(None)
            continue
        end = start + len(segment.raw_text)
        spans.append((start, end))
        search_start = end
    return spans


def _pipes_into(separator: str) -> bool:
    """Whether the text between two parsed commands pipes stdout into the next one.

    A pipeline stage's stdout belongs to its consumer, so a capture flag must not
    be injected there: ``curl -s ... | python3 -c 'json.load(sys.stdin)'`` would
    otherwise decode headers as JSON and silently degrade the probe. ``||`` is the
    logical-or operator - it runs the next command but does not consume this one's
    stdout - so it is not a pipe.
    """
    return "|" in separator and "||" not in separator


def _inside_command_substitution(command: str, position: int) -> bool:
    """Whether ``position`` sits inside an unclosed ``$(...)`` or backtick expansion.

    ``TOKEN=$(curl -s ...)`` captures the response into a shell variable, so the
    probe's stdout is consumed by the assignment rather than by the receipt.
    """
    prefix = command[:position]
    if prefix.count("`") % 2:
        return True
    return prefix.rfind("$(") >= 0 and prefix.count("(") > prefix.count(")")


def _stdout_is_captured(
    command: str,
    span: tuple[int, int],
    following: tuple[int, int] | None,
) -> bool:
    """Whether a probe's stdout is consumed somewhere other than the receipt.

    The injected status flag exists so the *captured evidence* carries a literal
    ``HTTP/1.x`` line. When stdout is piped into a program or captured by a shell
    variable, the prepended headers go to that consumer and corrupt it
    (``json.load``/``jq`` on a body with headers prepended) while telling the
    receipt nothing extra. A redirect to a file is *not* one of those cases: the
    file is the evidence, so the status line belongs in it.
    """
    if following is not None and _pipes_into(command[span[1] : following[0]]):
        return True
    return _inside_command_substitution(command, span[0])


def normalize_http_proof_flags(command: str) -> str:
    """Inject the client-specific flag into an HTTP probe missing status capture.

    Returns the original command unchanged unless it is an HTTP probe to an
    http(s) URL using curl/wget with no status-capture flag. Curl probes writing
    their body with ``-o`` use ``-w`` so the file remains parseable; other
    probes receive the client-specific header flag. Probes whose stdout is
    consumed by a pipe or command substitution are left alone.
    """
    segments = parse_bash_segments(command)
    spans = _segment_spans(command, segments)
    insertions: list[tuple[int, str]] = []
    for index, segment in enumerate(segments):
        client = segment.executable.casefold().removesuffix(".exe")
        if client not in _CLIENT_TOKEN_RE or not _HTTP_URL_RE.search(segment.raw_text):
            continue
        if has_capture_flag(segment.raw_text, client):
            continue
        span = spans[index]
        if span is None:
            continue
        following = spans[index + 1] if index + 1 < len(spans) else None
        if _stdout_is_captured(command, span, following):
            continue
        start = span[0]
        client_match = _CLIENT_TOKEN_RE[client].search(segment.raw_text)
        if client_match is None:
            continue
        capture_flag = _INJECTED_CAPTURE_FLAG[client]
        if client == "curl":
            try:
                tokens = shlex.split(segment.raw_text, posix=True)
            except ValueError:
                tokens = segment.raw_text.split()
            if any(
                token == "--output"
                or token.startswith("--output=")
                or (token.startswith("-o") and not token.startswith("--"))
                for token in tokens
            ):
                capture_flag = "-w 'HTTP %{http_code}\\n'"
        insertions.append((start + client_match.end(), f" {capture_flag}"))

    rewritten = command
    for position, value in reversed(insertions):
        rewritten = rewritten[:position] + value + rewritten[position:]
    return rewritten


__all__ = [
    "has_capture_flag",
    "normalize_http_proof_flags",
]
