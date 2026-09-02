"""Private, receipt-backed golden-set matching for submitted findings."""

from __future__ import annotations

import base64
import contextlib
import json
import re
import uuid
from dataclasses import dataclass
from http import HTTPStatus
from pathlib import Path
from typing import Any

from yarl import URL

from plugins.violin_guard.core.bash_ast import extract_all_command_words
from plugins.violin_guard.core.http_observations import (
    HTTP_METHODS,
    parse_http_observations,
    parse_http_statuses,
)
from plugins.violin_guard.core.receipt_integrity import verified_evidence_paths


@dataclass(frozen=True)
class RequestObservation:
    method: str
    url: URL


@dataclass(frozen=True)
class ProofBundle:
    receipt_path: Path
    command: str
    proof: str
    requests: tuple[RequestObservation, ...]
    executed: bool


@dataclass(frozen=True)
class EndpointSpec:
    method: str
    segments: tuple[str, ...]
    query_keys: frozenset[str]


def _read(path: Path, limit: int = 2 * 1024 * 1024) -> str:
    with path.open("r", encoding="utf-8", errors="replace") as handle:
        return handle.read(limit)


def _python_request_observations(source: str) -> list[RequestObservation]:
    """Parse python HTTP-client calls into request observations.

    Covers the two dominant scripted shapes:
    - ``urllib.request.Request('URL', data=..., method='VERB', ...)`` — the
      method kwarg wins; ``data=`` without a method means POST (urllib
      semantics: a body makes the request non-GET).
    - ``requests.<verb>('URL')`` / ``session.<verb>('URL')`` style clients.
    """
    observations: list[RequestObservation] = []
    for match in re.finditer(r"\bRequest\(\s*['\"](https?://[^'\"]+)['\"]([^)]*)", source):
        url, rest = match.group(1), match.group(2)
        method_match = re.search(r"method\s*=\s*['\"]([A-Z]+)['\"]", rest)
        if method_match:
            method = method_match.group(1)
        elif re.search(r"\bdata\s*=", rest):
            method = "POST"
        else:
            method = "GET"
        with contextlib.suppress(ValueError):
            observations.append(RequestObservation(method, URL(url)))
    for match in re.finditer(
        r"\b(?:requests|session|http)\s*\.\s*(get|post|put|delete|patch|head|options)\s*\(\s*['\"](https?://[^'\"]+)['\"]",
        source,
        re.IGNORECASE,
    ):
        with contextlib.suppress(ValueError):
            observations.append(RequestObservation(match.group(1).upper(), URL(match.group(2))))
    return observations


def _scripted_flow_requests(command: str, engagement: Path) -> tuple[RequestObservation, ...]:
    """Harvest URL+method observations from scripted HTTP flows.

    Two shapes are covered:
    - ``python3 evidence/vuln-research/probe.py`` — the URLs live in the script
      file referenced by path; read it (small, engagement-local).
    - ``python3 -c "<inline script>"`` — the URLs live in the command text.

    For each source: URL literals, python HTTP-client calls with exact
    methods, and ``call('POST', '/path')`` helper-driver invocations resolved
    against the source's base-URL literal (scheme+host only, so an endpoint
    URL inside the script doesn't get path-joined).
    """
    sources: list[str] = []
    # Inline python3 -c script bodies are the command text itself.
    if re.search(r"\b(?:python3?|node|ruby|perl)\b\s+-c\b", command):
        sources.append(command)
    for match in re.finditer(r"[\w./-]+\.(?:py|js|rb|pl)\b", command):
        candidate = (engagement / match.group(0)).resolve()
        if not candidate.is_file() or not candidate.is_relative_to(engagement.resolve()):
            continue
        with contextlib.suppress(OSError):
            sources.append(_read(candidate, 256 * 1024))

    requests: list[RequestObservation] = []
    for source in sources:
        # 1) python HTTP-client semantics: exact method per call site.
        requests.extend(_python_request_observations(source))
        # 2) full URL literals inside the script.
        for url_token in re.findall(r"https?://[^\s'\"<>)]+", source):
            with contextlib.suppress(ValueError):
                requests.append(RequestObservation("GET", URL(url_token)))
        # 3) helper-driver calls: call('POST', '/api/v1/orders/checkout', ...)
        #    resolved against the script's base-URL literal.
        base = re.search(r"https?://[^\s'\"<>)]+", source)
        if base:
            base_url = URL(base.group(0))
            root = f"{base_url.scheme}://{base_url.host}"
            if base_url.port:
                root += f":{base_url.port}"
            for call_match in re.finditer(
                r"\b(?:call|request|req|api|fetch|do_request)\(\s*['\"]([A-Z]+)['\"]\s*,\s*['\"]([^'\"]+)['\"]",
                source,
            ):
                method, path = call_match.group(1), call_match.group(2)
                if path.startswith("/"):
                    with contextlib.suppress(ValueError):
                        requests.append(RequestObservation(method, URL(root + path)))
    return tuple(dict.fromkeys(requests))


def _expand_shell_vars(command: str) -> str:
    """Textually expand ``VAR=url`` assignments and ``$VAR``/``${VAR}`` refs.

    Agents commonly set a base-URL shell variable (``export B=https://host/api``)
    and then ``curl $B/admin/users``. URL extraction only recognises literal
    ``http(s)://`` tokens, so without expansion those requests are invisible and
    every endpoint correlation fails. This rewrites ``$B/...`` back to a literal
    URL so the rest of the pipeline sees the real request. ``$(...)`` command
    substitution is left untouched (the opener ``$`` is followed by ``(``, not a
    variable name), so only true variable references are expanded.
    """
    if not command or "$" not in command:
        return command
    import re

    tokens: list[str]
    try:
        tokens = extract_all_command_words(command)
    except ValueError:
        tokens = command.split()
    if not tokens:
        tokens = command.split()
    env: dict[str, str] = {}
    for index, token in enumerate(tokens):
        name = token
        if token == "export" and index + 1 < len(tokens):
            name = tokens[index + 1]
        key, sep, value = name.partition("=")
        if sep and key and not key.startswith("$") and value.startswith(("http://", "https://")):
            env[key] = value
    if not env:
        return command
    pattern = re.compile(r"\$(?:\{([A-Za-z_][A-Za-z0-9_]*)\}|([A-Za-z_][A-Za-z0-9_]*))")

    def _replace(match: re.Match[str]) -> str:
        name = match.group(1) or match.group(2)
        return env.get(name, match.group(0))

    return pattern.sub(_replace, command)


def _command_requests(command: str) -> tuple[RequestObservation, ...]:
    # Use the guard's own bash-AST tokenizer, not shlex: shlex collapses
    # `sh -c 'python3 - <<PY ... curl https://... ...'` wrappers into a single
    # token and drops the URLs, while the AST extracts nested words.
    command = _expand_shell_vars(command)

    with contextlib.suppress(ValueError):
        tokens = extract_all_command_words(command)
        method = ""
        for index, token in enumerate(tokens[:-1]):
            if token in {"-X", "--request"}:
                method = tokens[index + 1].upper()
        if not method:
            method = (
                "POST"
                if any(
                    token in {"-d", "--data", "--data-raw", "--data-binary"}
                    or token.startswith("--data=")
                    for token in tokens
                )
                else "GET"
            )
        requests: list[RequestObservation] = []
        for token in tokens:
            if token.startswith(("http://", "https://")):
                with contextlib.suppress(ValueError):
                    requests.append(RequestObservation(method, URL(token)))
        # Scripted HTTP clients (python3/urllib inline, node, `python3 file.py`)
        # embed the target URL as a string literal inside the command — often
        # the only URL evidence for a flow that cannot be one curl. Extract
        # those literals so a decisive scripted flow is not dropped for lack
        # of a curl-shaped request. Skip URLs already observed so a plain
        # single-URL curl command still yields exactly one request (the
        # multi-request correlation guard depends on that count).
        for url_token in re.findall(r"https?://[^\s'\"<>)]+", command):
            with contextlib.suppress(ValueError):
                candidate = URL(url_token)
                if all(candidate != observed.url for observed in requests):
                    requests.append(RequestObservation("GET", candidate))
        return tuple(dict.fromkeys(requests))
    return ()


def _proof_requests(proof: str) -> tuple[RequestObservation, ...]:
    observations = [
        RequestObservation(value.method, value.url) for value in parse_http_observations(proof)
    ]
    for line in proof.splitlines():
        parts = line.strip().split()
        if len(parts) >= 3 and parts[0].upper() in HTTP_METHODS and parts[-1].startswith("HTTP/"):
            with contextlib.suppress(ValueError):
                observations.append(RequestObservation(parts[0].upper(), URL(parts[1])))
    return tuple(dict.fromkeys(observations))


def _partition_structured_proof(proof: str) -> list[str]:
    observations = parse_http_observations(proof)
    return [value.source for value in observations] if observations else [proof]


def receipt_bundles(
    engagement: Path,
    receipt_paths: list[str],
    *,
    evidence_paths: list[str] | None = None,
    receipt_key: str | bytes | None = None,
    receipt_public_key: str | bytes | None = None,
    trusted_fixture: bool = False,
) -> list[ProofBundle]:
    """Load evidence attached to one submitted finding.

    The decisive request/response body an agent saves to a separate evidence file
    (e.g. ``curl -o evidence/vuln-research/...``) is read as proof alongside the
    signed execution receipt that produced it, so a body the stdout only references
    still reaches the matcher.
    """
    bundles: list[ProofBundle] = []
    resolved_receipts: list[Path] = []
    receipt_stdouts: dict[Path, str] = {}
    for relative_value in receipt_paths:
        path = (engagement / relative_value).resolve()
        if trusted_fixture:
            if not path.is_file() or not path.is_relative_to((engagement / "evidence").resolve()):
                continue
            proof = _read(path)
            requests = _proof_requests(proof)
            for unit in _partition_structured_proof(proof):
                bundles.append(ProofBundle(path, "", unit, requests, True))
            continue

        if (
            not path.is_file()
            or path.suffix.lower() != ".json"
            or not path.is_relative_to((engagement / "evidence" / "executions").resolve())
        ):
            continue
        resolved_receipts.append(path)
        with contextlib.suppress(OSError, ValueError, json.JSONDecodeError):
            receipt = json.loads(_read(path))
            evidence = verified_evidence_paths(
                receipt,
                engagement,
                key=receipt_key,
                public_key=receipt_public_key,
            )
            if evidence is None:
                continue
            proof = "\n".join(_read(item) for item in evidence)
            receipt_stdouts[path] = proof
            proof_requests = _proof_requests(proof)
            command_requests = _command_requests(str(receipt.get("command") or ""))
            script_requests = _scripted_flow_requests(str(receipt.get("command") or ""), engagement)
            # Scripted-flow observations carry exact methods (PUT/POST via
            # python client semantics), so prefer them over raw URL tokens.
            requests = proof_requests or script_requests or command_requests
            # Unstructured multi-request batches cannot correlate a response to
            # a request — EXCEPT scripted single-flow commands (python3 -c
            # multi-step scripts, `python3 file.py`) whose every URL literal
            # belongs to one coherent scripted flow, so the bundle is still a
            # correlated unit even though it references several endpoints.
            scripted_flow = bool(
                re.search(
                    r"\b(?:python3?|node|ruby|perl)\b\s+(?:-c\s+\S|[^;&|]{1,200}\.(?:py|js|rb|pl)\b)",
                    str(receipt.get("command") or ""),
                )
            )
            if not proof_requests and len(command_requests) != 1 and not scripted_flow:
                continue
            executed = receipt.get("status") in {"completed", "timed_out", "output_limited"}
            executed = executed and receipt.get("exit_code") is not None
            for unit in _partition_structured_proof(proof):
                unit_requests = _proof_requests(unit) or requests
                bundles.append(
                    ProofBundle(
                        path,
                        str(receipt.get("command") or ""),
                        unit,
                        unit_requests,
                        executed,
                    )
                )

    # Attach saved decisive-evidence bodies (produced by a cited receipt).
    if evidence_paths and resolved_receipts:
        trusted_root = (engagement / "evidence").resolve()
        # Pre-load each receipt's command for per-file correlation below.
        receipt_commands = [_load_command(receipt_path) for receipt_path in resolved_receipts]
        for relative_value in evidence_paths:
            path = (engagement / relative_value).resolve()
            if (
                not path.is_file()
                or path.is_symlink()
                or not path.is_relative_to(trusted_root)
                or path.suffix.lower() == ".json"
            ):
                continue
            with contextlib.suppress(OSError):
                body = _read(path)
                # Correlate the body to the receipt whose command wrote it (by
                # filename reference), so a body saved without ``-i`` headers still
                # inherits that command's method/path AND command text — many
                # URL-bearing patterns (``/api/v1/orders/``, ``fetch-url``,
                # ``by-color``) live only in the command, not the saved body.
                name = path.name
                referenced_commands = [cmd for cmd in receipt_commands if name in cmd]
                command = " ".join(referenced_commands or receipt_commands)
                requests = _proof_requests(body)
                if not requests and referenced_commands:
                    # A compound command may run several curls; the body is the
                    # output of ONE of them. Extract requests from the specific
                    # sub-command that references this filename (split on the
                    # common command separators), so a body written by the second
                    # curl does not inherit the first curl's method/path.
                    requests = tuple(
                        dict.fromkeys(
                            req
                            for cmd in referenced_commands
                            for seg in _sub_commands(_expand_shell_vars(cmd))
                            if name in seg
                            for req in _command_requests(seg)
                        )
                    )
                    if not requests:
                        requests = tuple(
                            dict.fromkeys(
                                req for cmd in referenced_commands for req in _command_requests(cmd)
                            )
                        )
                # A scripted flow (`python3 probe.py | tee decisive.txt`) saves
                # its printed proof as the evidence body; the URLs live in the
                # script file. Harvest them so the body still yields endpoint
                # observations.
                if not requests:
                    requests = _scripted_flow_requests(command, engagement)
                # ``curl -o file -w 'HTTP %{http_code}'`` puts the status on the
                # receipt stdout, not in the saved body. If the body carries no
                # status line, inherit the status from the receipt whose command
                # actually wrote this body (filename reference), so
                # _positive_result can still see the 2xx/3xx status.
                proof = body
                if not parse_http_statuses(body):
                    for rp in resolved_receipts:
                        if name in _load_command(rp):
                            proof = f"{body}\n{receipt_stdouts.get(rp, '')}"
                            break
                for unit in _partition_structured_proof(proof):
                    bundles.append(ProofBundle(path, command, unit, requests or (), True))
    return bundles


def _load_command(receipt_path: Path) -> str:
    with contextlib.suppress(OSError, ValueError, json.JSONDecodeError):
        return str((json.loads(_read(receipt_path)) or {}).get("command") or "")
    return ""


def _sub_commands(command: str) -> list[str]:
    """Split a compound shell command into its top-level sub-commands.

    ``sh -c 'A; B && C'`` runs A, B, C as separate commands; a body saved by
    one of them must not inherit the requests of the others. Splitting on the
    common separators (``;``, ``&&``, ``||``, newline) recovers the segments so
    filename correlation can bind a body to the exact curl that wrote it.
    """
    import re

    return [segment for segment in re.split(r";|\n|&&|\|\|", command) if segment.strip()]


def endpoint_signature(value: str) -> EndpointSpec | None:
    endpoint = value.strip()
    first, separator, remainder = endpoint.partition(" ")
    if separator and first.upper() in HTTP_METHODS:
        method, target = first.upper(), remainder.strip()
    elif endpoint.startswith("/"):
        method, target = "", endpoint.replace("...", "", 1)
    else:
        return None
    url = URL(target)
    return EndpointSpec(
        method,
        tuple(segment for segment in url.path.split("/") if segment),
        frozenset(url.query.keys()),
    )


def _path_matches(template: tuple[str, ...], actual: tuple[str, ...]) -> bool:
    if len(template) != len(actual):
        return False
    for expected, observed in zip(template, actual, strict=True):
        if not (expected.startswith("{") and expected.endswith("}")):
            if expected != observed:
                return False
            continue
        parameter = expected[1:-1].lower()
        if parameter == "uuid":
            with contextlib.suppress(ValueError):
                uuid.UUID(observed)
                continue
            return False
        if parameter == "id" or parameter.endswith("_id"):
            if not observed.isdigit():
                return False
        elif not observed:
            return False
    return True


def _endpoint_matches(bundle: ProofBundle, raw_endpoint: str | list[str]) -> bool:
    endpoints = raw_endpoint if isinstance(raw_endpoint, list) else [raw_endpoint]
    specs = [endpoint_signature(str(value)) for value in endpoints]
    if any(spec is None for spec in specs):
        return bool(bundle.requests)
    for spec in specs:
        if spec is None:
            continue
        for request in bundle.requests:
            actual = tuple(segment for segment in request.url.path.split("/") if segment)
            if (
                (not spec.method or spec.method == request.method)
                and _path_matches(spec.segments, actual)
                and spec.query_keys.issubset(request.url.query.keys())
            ):
                return True
    return False


def _json_items(content: str) -> list[tuple[str, Any]]:
    def walk(value: Any) -> list[tuple[str, Any]]:
        result: list[tuple[str, Any]] = []
        if isinstance(value, dict):
            for key, child in value.items():
                result.append((str(key).casefold(), child))
                result.extend(walk(child))
        elif isinstance(value, list):
            for child in value:
                result.extend(walk(child))
        return result

    result: list[tuple[str, Any]] = []
    for line in content.splitlines():
        candidate = line.strip()
        # Scripted-client print form embeds JSON inside `LABEL (200, '{...}')`
        # tuples: extract the embedded JSON object so sentinel terms and
        # key/value patterns still see it.
        embedded = re.search(r"['\"](\{.*\})['\"]\s*\)?\s*$", candidate)
        if embedded:
            candidate = embedded.group(1)
        if not candidate.startswith(("{", "[")):
            continue
        with contextlib.suppress(json.JSONDecodeError):
            result.extend(walk(json.loads(candidate)))
    return result


def _sentinel(term: str, bundle: ProofBundle) -> bool:
    content = f"{bundle.command}\n{bundle.proof}"
    items = _json_items(bundle.proof)
    if term == "ADMIN_ADMIN_CREDENTIALS":
        compact = "".join(content.casefold().split())
        json_credentials = '"username":"admin"' in compact and '"password":"admin"' in compact
        form_credentials = "username=admin" in compact and "password=admin" in compact
        return json_credentials or form_credentials
    if term == "JWT_ALG_NONE_TOKEN":
        for match in re.finditer(r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*", content):
            token = match.group(0)
            header_segment, _payload_segment, signature_segment = token.split(".", maxsplit=2)
            padding = "=" * (-len(header_segment) % 4)
            with contextlib.suppress(ValueError, UnicodeDecodeError, json.JSONDecodeError):
                header = json.loads(
                    base64.urlsafe_b64decode(header_segment + padding).decode("utf-8")
                )
                if (
                    isinstance(header, dict)
                    and str(header.get("alg") or "").casefold() == "none"
                    and not signature_segment
                ):
                    return True
        return False
    if term == "NEGATIVE_NUMBER":
        return any(
            isinstance(value, int | float) and not isinstance(value, bool) and value < 0
            for _key, value in items
        )
    if term == "CREDIT_GRANTED":
        return any(
            key in {"credit", "account_credit"}
            and isinstance(value, int | float)
            and not isinstance(value, bool)
            and value > 0
            for key, value in items
        )
    if term == "ADMIN_ROLE_GRANTED":
        return any(key == "role" and str(value).casefold() == "admin" for key, value in items)
    if term == "ZERO_SHIPPING_COST":
        return any(key == "shipping_cost" and value == 0 for key, value in items)
    if term == "TOTP_BYPASSED":
        lowered = content.casefold().replace(" ", "")
        return any(value in lowered for value in ('"2fa":"bypassed"', '"bypass":true', '"totp":""'))
    if term == "REGULAR_USER_CONTEXT":
        lowered = content.casefold()
        return any(value in lowered for value in ("$user_token", "regular-user-token"))
    if term == "EXTERNAL_REDIRECT":
        for line in bundle.proof.splitlines():
            name, separator, value = line.partition(":")
            if separator and name.strip().casefold() == "location":
                location = URL(value.strip())
                if location.scheme in {"http", "https"} and location.host not in {
                    None,
                    "duck-store.escape.tech",
                    "localhost",
                    "127.0.0.1",
                }:
                    return True
    if term == "INTERNAL100":
        lowered = content.casefold()
        return "internal100" in lowered
    return False


def _terms_match(terms: list[str], bundle: ProofBundle, *, require_all: bool) -> bool:
    if not terms:
        return True
    content = f"{bundle.command}\n{bundle.proof}".casefold()
    matches = [
        _sentinel(term, bundle) if term.isupper() else term.casefold() in content for term in terms
    ]
    return all(matches) if require_all else any(matches)


def _positive_result(bundle: ProofBundle) -> bool:
    statuses = parse_http_statuses(bundle.proof)
    return bundle.executed and any(200 <= value < 400 for value in statuses)


def _absence_result(bundle: ProofBundle) -> bool:
    statuses = parse_http_statuses(bundle.proof)
    if not bundle.executed or len(statuses) < 8:
        return False
    common = max(set(statuses), key=statuses.count)
    return statuses.count(common) >= 8 and HTTPStatus.TOO_MANY_REQUESTS not in statuses


def bundle_matches_challenge(bundle: ProofBundle, challenge: dict[str, Any]) -> bool:
    """Apply one private golden verifier to one correlated receipt proof unit."""
    if not _endpoint_matches(bundle, challenge.get("endpoint") or ""):
        return False
    if not _terms_match(list(challenge.get("require") or []), bundle, require_all=True):
        return False
    if not _terms_match(list(challenge.get("require_any") or []), bundle, require_all=False):
        return False
    if not _terms_match(list(challenge.get("decisive_patterns") or []), bundle, require_all=False):
        return False
    if not _terms_match(list(challenge.get("patterns") or []), bundle, require_all=False):
        return False
    return _absence_result(bundle) if challenge.get("absence") else _positive_result(bundle)


def match_finding(
    engagement: Path,
    finding: dict[str, Any],
    challenges: list[dict[str, Any]],
    *,
    receipt_key: str | bytes | None = None,
    receipt_public_key: str | bytes | None = None,
    trusted_fixture: bool = False,
) -> tuple[str | None, list[str]]:
    """Return one unambiguous private golden key and all ambiguous candidates."""
    bundles = receipt_bundles(
        engagement,
        list(finding.get("receipt_paths") or []),
        evidence_paths=list(finding.get("evidence_paths") or []),
        receipt_key=receipt_key,
        receipt_public_key=receipt_public_key,
        trusted_fixture=trusted_fixture,
    )
    candidates = [
        str(challenge["id"])
        for challenge in challenges
        if any(bundle_matches_challenge(bundle, challenge) for bundle in bundles)
    ]
    return (candidates[0], candidates) if len(candidates) == 1 else (None, candidates)


__all__ = [
    "EndpointSpec",
    "ProofBundle",
    "RequestObservation",
    "bundle_matches_challenge",
    "endpoint_signature",
    "match_finding",
    "receipt_bundles",
]
