"""HTTP proof-capture helpers shared by command gates and the execution engine.

A target probe's saved evidence is only interpretable later (for scoring,
reporting, or replay) if it records a literal ``HTTP/1.x <code>`` status line.
Plain ``curl -s`` prints only the body and discards the status/headers. This
module provides a pure rewriter that injects ``-i`` into curl/wget HTTP probes
that lack any status-capture flag. It lives here (lower-level than both gates
and engine) so either layer can apply it without a circular import.
"""

from __future__ import annotations

import re
import shlex

_HTTP_CLIENT_RE = re.compile(r"\b(?:curl|wget)\b", re.I)
_HTTP_URL_RE = re.compile(r"https?://\S+", re.I)
_HTTP_LONG_FLAG_RE = re.compile(
    r"-(?:include|verbose|head|dump-header|write-out|output|remote-name|output-document)\b",
    re.I,
)
_HTTP_OFFLINE_CAPTURE_RE = re.compile(
    r"-(?:o|O|output|remote-name|output-document)\b|\s>\s*[^\s|]+", re.I
)

# Flags that already cause a status/header line to be captured or an explicit
# output file to be produced (curl: -i/--include, -I/--head, -D/--dump-header,
# -w/--write-out, -o/-O/--output; -v/--verbose includes headers. wget: -S).
_CAPTURE_SHORT_FLAGS = {"curl": "ivIDw", "wget": "S"}


def _detect_clients(command: str) -> list[str]:
    """Return the HTTP clients present in token order (curl / wget)."""
    try:
        tokens = shlex.split(command, posix=True)
    except ValueError:
        tokens = command.split()
    return [t for t in tokens if re.match(r"^(?:curl|wget)$", t, re.I)]


def _has_capture_short_flag(command: str) -> bool:
    """True if any present client already has a status-capture short flag.

    curl: -i include, -v verbose, -I head, -D dump-header, -w write-out.
    wget: -S server-response. `-s`/`-S`-cluster silent flags are NOT capture.
    """
    for client in _detect_clients(command) or ["curl"]:
        wanted = set(_CAPTURE_SHORT_FLAGS.get(client.lower(), ""))
        for token in re.findall(r"(?<!\S)-[A-Za-z]+", command):
            if any(ch in wanted for ch in token):
                return True
    return False


def normalize_http_proof_flags(command: str) -> str:
    """Inject ``-i`` into a curl/wget HTTP probe missing status capture.

    Returns the original command unchanged unless it is an HTTP probe to an
    http(s) URL using curl/wget with no status-capture flag, in which case
    ``-i`` is inserted immediately after the client token.
    """
    if not _HTTP_CLIENT_RE.search(command) or not _HTTP_URL_RE.search(command):
        return command
    if _HTTP_LONG_FLAG_RE.search(command) or _HTTP_OFFLINE_CAPTURE_RE.search(command):
        return command
    if _has_capture_short_flag(command):
        return command
    try:
        tokens = shlex.split(command, posix=True)
    except ValueError:
        tokens = command.split()
    rewritten: list[str] = []
    inserted = False
    for token in tokens:
        rewritten.append(token)
        if re.match(r"^(?:curl|wget)$", token, re.I) or token.startswith(
            ("./curl", "/usr/bin/curl", "curl.")
        ):
            rewritten.append("-i")
            inserted = True
    return " ".join(rewritten) if inserted else command
