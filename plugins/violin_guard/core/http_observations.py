"""Small, machine-readable HTTP evidence contract.

Batch probes may emit one JSON object per request using this shape::

    {"type":"http_observation","method":"GET","url":"https://target/path","status":200}

Literal HTTP response status lines are also accepted for single-request raw
captures. No prose or tool-specific output is inferred.
"""

from __future__ import annotations

import contextlib
import json
import re
from dataclasses import dataclass

from yarl import URL

HTTP_METHODS = frozenset({"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"})


@dataclass(frozen=True)
class HTTPObservation:
    method: str
    url: URL
    status: int
    source: str


def parse_http_observations(content: str) -> tuple[HTTPObservation, ...]:
    """Parse only explicitly structured JSONL HTTP observations."""
    observations: list[HTTPObservation] = []
    for line in content.splitlines():
        candidate = line.strip()
        if not candidate.startswith("{"):
            continue
        with contextlib.suppress(json.JSONDecodeError, TypeError, ValueError):
            value = json.loads(candidate)
            if not isinstance(value, dict) or value.get("type") != "http_observation":
                continue
            method = str(value["method"]).upper()
            url = URL(str(value["url"]))
            status = int(value["status"])
            if method in HTTP_METHODS and url.scheme in {"http", "https"} and 100 <= status <= 599:
                observations.append(HTTPObservation(method, url, status, candidate))
    return tuple(observations)


def parse_http_statuses(content: str) -> tuple[int, ...]:
    """Parse structured observations, exact HTTP status-line forms, the
    ``-w '[\\n%{http_code}\\n]'`` bracket form, and the ``-w 'HTTPCODE:%{http_code}'``
    form the guard recommends — plus the bare ``-w '%{http_code} '`` form that
    emits a line of space-separated status codes (e.g. a rate-limit burst probe)."""
    statuses = [observation.status for observation in parse_http_observations(content)]
    for line in content.splitlines():
        parts = line.strip().split()
        if not parts:
            continue
        # HTTP/1.1 200 or HTTP 200 status-line form.
        if (
            parts[0].upper() in {"HTTP", "HTTP/1.0", "HTTP/1.1", "HTTP/2", "HTTP/3"}
            and len(parts) >= 2
        ):
            with contextlib.suppress(ValueError):
                status = int(parts[1])
                if 100 <= status <= 599:
                    statuses.append(status)
            continue
        # curl -w '%{http_code}' bracket form: [200] or [200] ...
        if parts[0].startswith("[") and parts[0].endswith("]"):
            with contextlib.suppress(ValueError):
                status = int(parts[0][1:-1])
                if 100 <= status <= 599:
                    statuses.append(status)
            continue
        # curl -w 'HTTPCODE:%{http_code}' form: HTTPCODE:200
        if parts[0].upper().startswith("HTTPCODE:"):
            with contextlib.suppress(ValueError):
                status = int(parts[0].split(":")[-1])
                if 100 <= status <= 599:
                    statuses.append(status)
            continue
        # Scripted-client print form: `LABEL (200, '{...}')` or `(200, ...)` —
        # python-repr status tuple printed by a urllib/requests probe script.
        # The status may land in its own token (`(200,`) or glom onto a
        # preceding label token (`LABEL(200,`), so strip both sides.
        tuple_match = re.match(
            r"^(?:[A-Za-z_][A-Za-z0-9_]*\s*)?\(\s*(\d{3})\s*[,)]",
            line.strip(),
        )
        if tuple_match and _is_status_code_token(tuple_match.group(1)):
            statuses.append(int(tuple_match.group(1)))
            continue
        # Scripted-client summary form: `LABEL statuses: {401: 15}` — a
        # python-repr dict of status→count printed by a burst probe script.
        # Expand counts so absence proofs (N identical statuses, no 429) see
        # the true repetition count, not one collapsed observation.
        dict_match = re.search(
            r"statuses:\s*\{(\d{3}\s*:\s*\d+(?:\s*,\s*\d{3}\s*:\s*\d+)*)\s*\}", line
        )
        if dict_match:
            for status_token, count_token in re.findall(
                r"(\d{3})\s*:\s*(\d+)", dict_match.group(1)
            ):
                statuses.extend([int(status_token)] * int(count_token))
            continue
        # Bare form: a line of only 3-digit HTTP status codes (100-599),
        # e.g. `-w '%{http_code} '` on a rapid burst probe: "401 401 401 ...".
        if all(_is_status_code_token(token) for token in parts):
            statuses.extend(int(token) for token in parts)
            continue
        # Labeled burst form: `-w "req $i %{http_code}\\n"` emits "req 1 401".
        # The status is the final token; every preceding token is a label word
        # or a short sequence counter (never another 3-digit status).
        if (
            len(parts) >= 2
            and _is_status_code_token(parts[-1])
            and all(not _is_status_code_token(token) for token in parts[:-1])
        ):
            statuses.append(int(parts[-1]))
            continue
        # `-w '%{http_code} '` immediately followed by the response body on the
        # same line: "200 [{\"id\":...}" or "400 {\"detail\":...}". The leading
        # 3-digit token is the status; the rest is body.
        if (
            _is_status_code_token(parts[0])
            and len(parts) >= 2
            and parts[1].startswith(("{", "[", "<", '"', "'"))
        ):
            statuses.append(int(parts[0]))
    return tuple(statuses)


def _is_status_code_token(token: str) -> bool:
    return len(token) == 3 and token.isdigit() and 100 <= int(token) <= 599


__all__ = ["HTTP_METHODS", "HTTPObservation", "parse_http_observations", "parse_http_statuses"]
