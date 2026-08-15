"""Shared, provenance-aware benchmark proof evaluation."""

from __future__ import annotations

import contextlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from plugins.violin_guard.receipt_integrity import verified_evidence_paths

_HTTP_RESPONSE_RE = re.compile(r"HTTP/\d(?:\.\d)?\s+[1-5]\d{2}", re.IGNORECASE)
_HTTP_REQUEST_RE = re.compile(
    r"\b(?:GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+/\S+\s+HTTP", re.IGNORECASE
)
# Keep evidence references path-shaped.  Shell upload arguments commonly append
# `;type=...` or `;filename=...` to an evidence path; those fragments are not
# part of the referenced file and must not make an otherwise valid citation
# look broken.
_EVIDENCE_REF_RE = re.compile(r"evidence/[A-Za-z0-9_./-]+")
_GENERIC_PATTERNS = frozenset({"100", "admin", "password", "role", "username", "uuid"})


@dataclass(frozen=True)
class EvidenceBundle:
    """One request/output proof unit, never a state or reporting summary."""

    primary_path: Path
    relative_path: str
    context: str
    proof: str
    files: tuple[Path, ...]
    executed: bool


def _read(path: Path, limit: int = 2 * 1024 * 1024) -> str:
    if path.stat().st_size > limit:
        with path.open("r", encoding="utf-8", errors="replace") as handle:
            return handle.read(limit)
    return path.read_text(encoding="utf-8", errors="replace")


def collect_evidence_bundles(
    eng_dir: Path,
    *,
    receipt_key: str | bytes | None = None,
    trusted_fixture: bool = False,
) -> list[EvidenceBundle]:
    """Build authenticated execution bundles or explicitly trusted fixture bundles."""
    engagement = eng_dir.resolve()
    evidence = engagement / "evidence"
    if not evidence.exists():
        return []
    bundles: list[EvidenceBundle] = []
    claimed: set[Path] = set()
    executions = evidence / "executions"
    for manifest in sorted(executions.glob("*.json")) if executions.exists() else []:
        with contextlib.suppress(OSError, json.JSONDecodeError):
            data = json.loads(_read(manifest))
            if not isinstance(data, dict) or not data.get("execution_id"):
                continue
            declared_manifest = str((data.get("evidence_paths") or {}).get("manifest") or "")
            declared_path = (
                (engagement / declared_manifest).resolve() if declared_manifest else None
            )
            if declared_path != manifest.resolve():
                continue
            verified = verified_evidence_paths(data, engagement, key=receipt_key)
            if verified is None:
                continue
            output_files = list(verified)
            output_parts: list[str] = []
            command = str(data.get("command") or "")
            for candidate in output_files:
                output_parts.append(_read(candidate))
                claimed.add(candidate)
            proof = "\n".join(output_parts)
            relative_manifest = manifest.relative_to(engagement).as_posix()
            bundles.append(
                EvidenceBundle(
                    manifest,
                    relative_manifest,
                    "\n".join((relative_manifest, command, proof)),
                    proof,
                    (manifest, *output_files),
                    data.get("status") in {"completed", "timed_out", "output_limited"}
                    and data.get("exit_code") is not None,
                )
            )
            claimed.add(manifest)

    if not trusted_fixture:
        return bundles

    excluded_roots = {evidence / "reporting", evidence / "findings"}
    for path in sorted(item for item in evidence.rglob("*") if item.is_file()):
        resolved_path = path.resolve()
        if resolved_path in claimed or any(path.is_relative_to(root) for root in excluded_roots):
            continue
        if path.suffix.lower() in {".lock", ".tmp", ".py", ".sh", ".pl", ".rb"}:
            continue
        with contextlib.suppress(OSError):
            content = _read(path)
            relative = path.relative_to(engagement).as_posix()
            bundles.append(
                EvidenceBundle(path, relative, f"{relative}\n{content}", content, (path,), True)
            )
    return bundles


def endpoint_signature(endpoint: str) -> tuple[str, re.Pattern[str] | None]:
    value = endpoint.strip()
    match = re.match(r"^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+(.+)$", value, re.I)
    if not match:
        return "", None
    method, route = match.group(1).upper(), match.group(2).strip()
    parts: list[str] = []
    cursor = 0
    for parameter in re.finditer(r"\{[^}]+\}", route):
        parts.append(re.escape(route[cursor : parameter.start()]))
        parts.append(r"[^/?\s\"']+")
        cursor = parameter.end()
    parts.append(re.escape(route[cursor:]))
    pattern = re.compile("".join(parts) + r"(?=[?\s\"']|$)", re.IGNORECASE)
    return method, pattern


def _endpoint_matches(bundle: EvidenceBundle, endpoint: str) -> bool:
    method, route = endpoint_signature(endpoint)
    if route is None or not route.search(bundle.context):
        return False
    if re.search(rf"\b{method}\s+(?:https?://[^/\s]+)?{route.pattern}", bundle.context, re.I):
        return True
    if bundle.primary_path.suffix.lower() != ".json":
        return False
    command = bundle.context.splitlines()[1] if len(bundle.context.splitlines()) > 1 else ""
    explicit = re.search(r"(?:-X|--request)\s+([A-Z]+)", command, re.IGNORECASE)
    inferred = (
        explicit.group(1).upper()
        if explicit
        else "POST"
        if re.search(r"(?:^|\s)(?:-d|--data(?:-raw|-binary|-urlencode)?)\b", command)
        else "GET"
    )
    return inferred == method


def pattern_hits(patterns: list[str], content: str) -> set[str]:
    lowered = content.lower()
    return {pattern for pattern in patterns if pattern.lower() in lowered}


# Require-term sentinels resolved against the raw (un-lowered) content.
_NEGATIVE_NUMBER_RE = re.compile(r"-\d+")
_CREDIT_GRANTED_RE = re.compile(r"(?:account_)?credit\"\s*:\s*(?:[1-9]\d*|0\.\d*[1-9]\d*)", re.I)
_ADMIN_ROLE_GRANTED_RE = re.compile(r'role\s*[":=]+\s*admin', re.I)
_EXTERNAL_REDIRECT_RE = re.compile(r"location\s*:\s*https?://(?!duck-store|localhost|127\.)", re.I)

_SENTINEL_RESOLVERS = {
    "NEGATIVE_NUMBER": _NEGATIVE_NUMBER_RE,
    "CREDIT_GRANTED": _CREDIT_GRANTED_RE,
    "ADMIN_ROLE_GRANTED": _ADMIN_ROLE_GRANTED_RE,
    "EXTERNAL_REDIRECT": _EXTERNAL_REDIRECT_RE,
}


def require_hits(require_terms: list[str], content: str) -> bool:
    """All require terms must hit. Sentinels expand to regexes; the rest are substrings."""
    lowered = content.lower()
    for term in require_terms:
        resolver = _SENTINEL_RESOLVERS.get(term)
        if resolver is not None:
            if not resolver.search(content):
                return False
        elif term.lower() not in lowered:
            return False
    return True


def require_any_hits(require_any_terms: list[str], content: str) -> bool:
    """At least one require-any term must hit (shared-endpoint discriminator)."""
    lowered = content.lower()
    for term in require_any_terms:
        resolver = _SENTINEL_RESOLVERS.get(term)
        if resolver is not None:
            if resolver.search(content):
                return True
        elif term.lower() in lowered:
            return True
    return False


def _absence_proven(bundle: EvidenceBundle) -> bool:
    """Absence-type finding: repeated identical status codes, no counter-signal.

    The proof of a missing rate limit is a run of identical responses (e.g.
    15x 401) with no 429/throttle/lockout anywhere in the output. This is the
    inverse of the usual proof-quality gate: for absence challenges the
    repeated-status sequence IS the decisive output.
    """
    proof = bundle.proof
    if not bundle.executed or len(proof.strip()) < 20:
        return False
    statuses = re.findall(r"(?<![\d.])([1-5]\d{2})(?![\d])", proof)
    if len(statuses) < 8:
        return False
    most_common = max(set(statuses), key=statuses.count)
    return statuses.count(most_common) >= 8 and not re.search(
        r"\b(?:429|throttl|rate.?limit|lockout)\b", proof, re.I
    )


def has_decisive_proof(bundle: EvidenceBundle) -> bool:
    """Require output evidence; a command or manifest alone is never proof."""
    proof = bundle.proof.strip()
    if not bundle.executed or len(proof) < 20:
        return False
    if _HTTP_RESPONSE_RE.search(proof):
        if _HTTP_REQUEST_RE.search(bundle.context):
            return True
        if (
            bundle.primary_path.suffix.lower() == ".json"
            and len(bundle.files) > 1
            and re.search(r"https?://\S+", bundle.context, re.IGNORECASE)
        ):
            return True
    with contextlib.suppress(json.JSONDecodeError):
        payload = json.loads(proof)
        if isinstance(payload, dict | list) and len(payload) > 0:
            return True
    return False


def bundle_matches_challenge(bundle: EvidenceBundle, challenge: dict[str, Any]) -> bool:
    """Endpoint/method + decisive proof is the evidence; patterns corroborate.

    Ground-truth patterns written against walkthrough-internal response key
    names (UserList, OrderDetail, ...) never appear in live app traffic, so an
    exact endpoint+method hit with decisive output is accepted with a single
    pattern hit. Generic-only patterns on shared endpoints (e.g. auth/login)
    are gated by explicit ``require`` discriminators, and absence-type
    challenges (missing rate limit) match on repeated identical status codes.
    """
    content = bundle.context.lower()
    challenge_id = str(challenge.get("id") or "").lower()
    raw_endpoints = challenge.get("endpoint") or ""
    endpoints = raw_endpoints if isinstance(raw_endpoints, list) else [str(raw_endpoints)]
    endpoints = [str(ep) for ep in endpoints if str(ep).strip()]
    filename_anchored = challenge_id in bundle.relative_path.lower()
    patterns = [str(value) for value in challenge.get("patterns", []) if str(value).strip()]
    hits = pattern_hits(patterns, content)
    decisive_patterns = [
        str(value) for value in challenge.get("decisive_patterns", []) if str(value).strip()
    ]
    if decisive_patterns and not pattern_hits(decisive_patterns, content):
        return False
    require = [str(value) for value in challenge.get("require", []) if str(value).strip()]
    if require and not require_hits(require, content):
        return False
    require_any = [str(value) for value in challenge.get("require_any", []) if str(value).strip()]
    if require_any and not require_any_hits(require_any, content):
        return False
    specific_hits = {
        hit
        for hit in hits
        if hit.lower() not in _GENERIC_PATTERNS and not hit.strip().startswith("/")
    }
    endpoint_anchored = any(_endpoint_matches(bundle, ep) for ep in endpoints)
    no_fixed_endpoint = any(endpoint_signature(ep)[1] is None for ep in endpoints)

    # Absence-type findings: a run of identical status codes IS the proof.
    if challenge.get("absence") and endpoint_anchored and _absence_proven(bundle):
        return True

    if no_fixed_endpoint:
        anchored = len(specific_hits) >= 2
        relevant = len(specific_hits) >= 2
    elif filename_anchored or endpoint_anchored:
        anchored = True
        relevant = bool(hits)
    else:
        anchored = False
        relevant = len(specific_hits) >= 2
    return bool(anchored and relevant and has_decisive_proof(bundle))


def evaluate_technical_proof(
    eng_dir: Path,
    challenges: list[dict[str, Any]],
    *,
    receipt_key: str | bytes | None = None,
    trusted_fixture: bool = False,
) -> dict[str, list[EvidenceBundle]]:
    bundles = collect_evidence_bundles(
        eng_dir,
        receipt_key=receipt_key,
        trusted_fixture=trusted_fixture,
    )
    return {
        str(challenge["id"]): [
            bundle for bundle in bundles if bundle_matches_challenge(bundle, challenge)
        ]
        for challenge in challenges
    }


def evidence_references(text: str) -> set[str]:
    return {match.rstrip(".:") for match in _EVIDENCE_REF_RE.findall(text)}


def broken_evidence_references(eng_dir: Path, texts: list[str]) -> list[str]:
    broken: set[str] = set()
    evidence_root = (eng_dir / "evidence").resolve()
    for reference in {item for text in texts for item in evidence_references(text)}:
        relative = Path(reference)
        candidate = (eng_dir / relative).resolve()
        if (
            relative.is_absolute()
            or not candidate.is_relative_to(evidence_root)
            or not candidate.is_file()
            or candidate.stat().st_size == 0
        ):
            broken.add(reference)
    return sorted(broken)


# ---------------------------------------------------------------------------
# Finding-file confirmation (live-app contract)
# ---------------------------------------------------------------------------
def parse_hypotheses(text: str) -> list[dict]:
    """Parse each ### H-XXX: block, extract Status, Linked challenges, Linked findings, and evidence references."""
    blocks = re.split(r"\n(?=### H-\d+:)", text)
    results = []
    for block in blocks:
        m = re.match(r"^### (H-\d+):", block)
        if not m:
            continue
        hid = m.group(1)
        status = "Candidate"
        linked: list[str] = []
        linked_findings: list[str] = []
        evidence_files: set[str] = set()

        for line in block.splitlines():
            sline = line.strip()
            sm = re.match(r"^(?:[-*]\s*)?\*\*Status:\*\*\s*(.+)", sline, re.IGNORECASE)
            if sm:
                status = sm.group(1).strip()
            lcm = re.match(r"^(?:[-*]\s*)?\*\*Linked challenges:\*\*\s*(.+)", sline, re.IGNORECASE)
            if lcm:
                raw = lcm.group(1)
                linked = [s.strip() for s in raw.split(",") if s.strip()]
            lfm = re.match(r"^(?:[-*]\s*)?\*\*Linked findings:\*\*\s*(.+)", sline, re.IGNORECASE)
            if lfm:
                raw = lfm.group(1)
                linked_findings = [s.strip() for s in raw.split(",") if s.strip()]
            if "evidence/" in line:
                for part in re.findall(r"evidence/[^\s,)`\]]+", line):
                    evidence_files.add(Path(part).name)

        results.append(
            {
                "id": hid,
                "status": status,
                "linked": linked,
                "linked_findings": linked_findings,
                "evidence_files": evidence_files,
                "text": block,
            }
        )
    return results


def parse_findings(eng_dir: Path) -> list[dict]:
    """Parse evidence/findings/FIND-*.md files to map findings to evidence files."""
    findings_dir = eng_dir / "evidence" / "findings"
    if not findings_dir.exists():
        return []
    results = []
    for fpath in findings_dir.glob("FIND-*.md"):
        try:
            txt = fpath.read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue
        fid = fpath.stem
        evidence_files: set[str] = set()
        linked_hypotheses: set[str] = set()
        for line in txt.splitlines():
            if "evidence/" in line:
                for part in re.findall(r"evidence/[^\s,)`\]]+", line):
                    evidence_files.add(Path(part).name)
            hyp_link = re.search(
                r"linked\s+hypothes[ie]s?\s*:?\s*[*:\-]*\s*(H-\d+)",
                line,
                re.IGNORECASE,
            )
            if hyp_link:
                linked_hypotheses.add(hyp_link.group(1).upper())
        results.append(
            {
                "id": fid,
                "evidence_files": evidence_files,
                "linked_hypotheses": linked_hypotheses,
                "text": txt,
            }
        )
    return results


def method_route_in_text(text: str, method: str, route: re.Pattern[str]) -> bool:
    """METHOD + route in prose, accepting findings that drop the /api/v1 prefix.

    Also accepts curl-form reproduction commands: ``-X POST 'https://…'``
    with optional quotes around the URL (the quote must not break the match).
    """
    variants = [route.pattern]
    api_v1_stripped = route.pattern.replace("/api/v1/", "/", 1)
    if api_v1_stripped != route.pattern:
        variants.append(api_v1_stripped)
    return any(
        re.search(
            rf"(?:-X\s+)?\b{method}\s*['\"]?(?:https?://[^/\s'\"]+)?{variant}",
            text,
            re.I,
        )
        for variant in variants
    )


def finding_matches_challenge(text: str, challenge: dict) -> bool:
    """Match a canonical finding file against a challenge using live-app terms.

    A finding file is the agent's written PoC claim. It confirms a challenge
    when it names the exact METHOD + endpoint route (with /api/v1 optional),
    hits at least one detection pattern, and satisfies any ``require``
    discriminators. No-fixed-endpoint challenges (e.g. JWT anywhere, open
    redirect) need at least two specific terms. The finding must be
    substantive — a one-line mention is never proof.
    """
    if len(text.strip()) < 100:
        return False
    raw_endpoints = challenge.get("endpoint") or ""
    endpoints = raw_endpoints if isinstance(raw_endpoints, list) else [str(raw_endpoints)]
    endpoints = [str(ep) for ep in endpoints if str(ep).strip()]
    require = [str(value) for value in challenge.get("require", []) if str(value).strip()]
    if require and not require_hits(require, text):
        return False
    require_any = [str(value) for value in challenge.get("require_any", []) if str(value).strip()]
    if require_any and not require_any_hits(require_any, text):
        return False
    patterns = [str(value) for value in challenge.get("patterns", []) if str(value).strip()]
    hits = pattern_hits(patterns, text)
    decisive_patterns = [
        str(value) for value in challenge.get("decisive_patterns", []) if str(value).strip()
    ]
    if decisive_patterns and not pattern_hits(decisive_patterns, text):
        return False
    specific_hits = {
        hit
        for hit in hits
        if hit.lower() not in _GENERIC_PATTERNS and not hit.strip().startswith("/")
    }
    fixed = [(m, r) for ep in endpoints for m, r in [endpoint_signature(ep)] if r is not None]
    if not fixed:
        return len(specific_hits) >= 2
    for method, route in fixed:
        if method_route_in_text(text, method, route):
            return bool(hits)
    return False


def finding_confirmed_challenge_ids(
    hypotheses: list[dict],
    findings: list[dict],
    challenges: list[dict],
) -> dict[str, list[str]]:
    """Map Validated hypotheses' linked findings to confirmed challenge IDs.

    Returns {challenge_id: [finding paths]} for findings that match a
    challenge in live-app terms. This recovers confirmations when execution
    evidence was truncated by ``tail -c`` and no longer matches bundle rules,
    while keeping the paper-trail floor: the finding must be substantive,
    cite evidence, and be linked from a Validated hypothesis.
    """
    texts_by_id = {finding["id"]: finding["text"] for finding in findings}
    confirmed: dict[str, list[str]] = {}
    for hypothesis in hypotheses:
        if hypothesis["status"].strip().lower() != "validated":
            continue
        hyp_text = hypothesis.get("text", "")
        for finding_id in hypothesis.get("linked_findings", []):
            text = texts_by_id.get(finding_id)
            if not text:
                continue
            # The hypothesis block is part of the validated claim — findings
            # sometimes write "METHOD /path" only in the hypothesis rationale.
            combined = f"{hyp_text}\n{text}"
            for challenge in challenges:
                if finding_matches_challenge(combined, challenge):
                    confirmed.setdefault(challenge["id"], []).append(
                        f"evidence/findings/{finding_id}.md"
                    )
    return confirmed


__all__ = [
    "EvidenceBundle",
    "broken_evidence_references",
    "bundle_matches_challenge",
    "collect_evidence_bundles",
    "evaluate_technical_proof",
    "endpoint_signature",
    "evidence_references",
    "finding_confirmed_challenge_ids",
    "finding_matches_challenge",
    "has_decisive_proof",
    "method_route_in_text",
    "parse_findings",
    "parse_hypotheses",
    "pattern_hits",
    "require_any_hits",
    "require_hits",
]
