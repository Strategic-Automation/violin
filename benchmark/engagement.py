"""Benchmark scope generation and engagement setup."""

import copy
import ipaddress
import shutil
import tempfile
from datetime import date
from pathlib import Path

import yaml
from yarl import URL

from plugins.violin_guard.gates.command import validate_scope

REPO_ROOT = Path(__file__).resolve().parent.parent

_COVERAGE_OBLIGATIONS = (
    "POST /api/v1/auth/login",
    "POST /api/v1/auth/login/totp",
    "POST /api/v1/auth/register",
    "GET /api/v1/users/",
    "GET /api/v1/users/{uuid}",
    "PUT /api/v1/users/me/profile",
    "GET /api/v1/products/filter/by-color",
    "POST /api/v1/testimonials/",
    "PUT /api/v1/testimonials/{id}",
    "POST /api/v1/uploads/import-from-url",
    "GET /api/v1/uploads/fetch-url",
    "GET /api/v1/orders/{id}",
    "GET /api/v1/admin/users",
    "POST /api/v1/cart/add",
    "PUT /api/v1/cart/items/{id}",
    "POST /api/v1/orders/checkout",
    "GET /api/v1/orders/coupons",
    "/...?redirect=",
)


def _scope_for_target(target: str) -> dict:
    """Render the canonical benchmark fixture for one URL, domain, or IP target."""
    fixture_path = REPO_ROOT / "benchmark" / "targets" / "duck-store" / "scope.yaml"
    scope = copy.deepcopy(yaml.safe_load(fixture_path.read_text(encoding="utf-8")))
    raw_target = target.strip()
    parsed = URL(raw_target if "://" in raw_target else f"https://{raw_target}")
    if parsed.scheme not in {"http", "https"} or not parsed.host:
        raise ValueError("benchmark target must be an HTTP(S) URL, domain, or IP address")
    host = parsed.host
    try:
        ipaddress.ip_address(host)
        addresses = [host]
        domains: list[str] = []
    except ValueError:
        addresses = []
        domains = [host]
    base_url = str(parsed.with_path("").with_query(None).with_fragment(None)).rstrip("/")
    scope["engagement"]["date"] = date.today().isoformat()
    scope["targets"] = {
        "ip_addresses": addresses,
        "domains": domains,
        "urls": [str(parsed)],
        "in_scope_urls": [str(parsed)],
    }
    excluded_paths = list((scope.get("exclusions") or {}).get("paths") or [])
    scope.setdefault("exclusions", {})["urls"] = [
        f"{base_url}/{path.lstrip('/')}" for path in excluded_paths
    ]
    benchmark = scope.get("benchmark")
    if isinstance(benchmark, dict):
        benchmark["openapi_spec"] = f"{base_url}/openapi.json"
    # Engagement brief (client-provided facts, framework-owned): seed the
    # target's engage.md so operational facts (default credentials, register
    # first, reset window) reach the agent via scope.yaml — the file the agent
    # is already required to validate — instead of the prompt. The /goal prompt
    # stays task-only.
    brief_path = fixture_path.with_name("engage.md")
    if brief_path.is_file():
        brief = (
            brief_path.read_text(encoding="utf-8")
            .replace("https://duck-store.escape.tech", base_url)
            .strip()
        )
        if brief:
            scope.setdefault("engagement", {})["brief"] = brief
    # Engagement audit mode: a generic "structured engagement" flag the
    # framework gates on. Benchmark harness sets it; a real client engagement
    # with strict record-keeping can set the same flag. No benchmark concept
    # leaks into framework logic.
    scope.setdefault("engagement", {})["audit_mode"] = True
    # Strict engagement record-keeping: every WSTG methodology category must be
    # dispositioned with evidence before VULN_RESEARCH closes. Same generic
    # client-style flag as audit_mode; a real strict client can set it too.
    scope.setdefault("engagement", {})["require_methodology_gates"] = True
    # Coverage obligations: route-level API scope a client would provide at
    # kickoff (in-scope endpoints), NOT vulnerability names — the agent must
    # still discover what is vulnerable. Derived from the target's endpoint
    # inventory; the framework's coverage gate then requires an evidence-backed
    # matrix cell per obligation.
    scope.setdefault("engagement", {})["coverage_obligations"] = list(_COVERAGE_OBLIGATIONS)
    return scope


def init_benchmark_engagement(eng_dir: Path, target: str) -> None:
    """Initialize benchmark engagement directory structure cleanly (idempotent reset)."""
    resolved_eng = eng_dir.resolve()
    resolved_engagements = (REPO_ROOT / "engagements").resolve()
    temporary_root = Path(tempfile.gettempdir()).resolve()
    pytest_root = (REPO_ROOT / ".pytest-tmp").resolve()
    if not (
        resolved_eng == resolved_engagements
        or resolved_engagements in resolved_eng.parents
        or temporary_root in resolved_eng.parents
        or pytest_root in resolved_eng.parents
    ):
        raise ValueError(
            f"Safety error: engagement directory {resolved_eng} must be inside {resolved_engagements}"
        )

    if eng_dir.exists():
        for item in eng_dir.iterdir():
            if item.is_dir() and not item.is_symlink():
                shutil.rmtree(item)
            else:
                item.unlink(missing_ok=True)

    eng_dir.mkdir(parents=True, exist_ok=True)
    (eng_dir / "scope").mkdir(parents=True, exist_ok=True)
    (eng_dir / "state").mkdir(parents=True, exist_ok=True)
    (eng_dir / "evidence").mkdir(parents=True, exist_ok=True)
    for phase_dir in (
        "recon",
        "recon/active",
        "recon/passive",
        "vuln-research",
        "exploitation",
        "post-exploitation",
        "privesc",
        "flags",
        "reporting",
        "retrospective",
        "executions",
    ):
        (eng_dir / "evidence" / phase_dir).mkdir(parents=True, exist_ok=True)
    (eng_dir / "exploits").mkdir(parents=True, exist_ok=True)

    scope_yaml = eng_dir / "scope" / "scope.yaml"
    scope_yaml.write_text(
        yaml.safe_dump(_scope_for_target(target), sort_keys=False), encoding="utf-8"
    )
    validation = validate_scope(scope_yaml)
    if validation.errors:
        raise ValueError("generated benchmark scope is invalid: " + "; ".join(validation.errors))

    ptt_md = eng_dir / "state" / "ptt.md"
    ptt_md.write_text(
        """# Pentesting Task Tree (PTT)

## Phase: RECON

| ID | Status | Task | Notes |
|---|---|---|---|
| PT-101 | [~] | Reconnaissance & Tech Detection | benchmark bootstrap; record exact request/response evidence |

## Phase: VULN_RESEARCH

| ID | Status | Task | Notes |
|---|---|---|---|
| PT-102 | [ ] | Vulnerability Assessment | test and disposition every mapped route, method, parameter, and role boundary |

## Phase: EXPLOITATION

| ID | Status | Task | Notes |
|---|---|---|---|
| PT-103 | [ ] | Exploitation & Proof Verification | validate only in-scope, non-destructive findings |
""",
        encoding="utf-8",
    )

    hyp_md = eng_dir / "hypotheses.md"
    hyp_md.write_text(
        """# Hypothesis Board
### H-001: Initial Target Assessment
**Status:** Candidate
""",
        encoding="utf-8",
    )

    feedback_md = eng_dir / "state" / "framework_feedback.md"
    feedback_md.write_text(
        """# Violin Framework Feedback & Friction Log
If you encounter tool friction, missing binaries/CLI tools, guard pathing errors, or framework bugs in Violin during this assessment, record them below.

CRITICAL: Whenever you inspect or read the guard codebase (e.g. plugins/violin_guard/ or guard scripts) to understand how a tool works, why a command was blocked, or how state is managed, log the occurrence below with:
1. Category: Guard Code Inspection
2. Issue Description: Which guard file/code you read and what you were trying to understand
3. Impact / Workaround: What confusion or error forced you to read the code
4. Prevention Suggestion: What specifically would prevent needing to read guard code in the future (e.g. clearer error messages, self-documenting CLI parameters, tool docs, or explicit return details)

| Timestamp | Category | Issue Description | Impact / Workaround | Prevention Suggestion |
|---|---|---|---|---|
""",
        encoding="utf-8",
    )

    # Seed the matrix from the exact client-style obligations in scope.yaml.
    # The close gate requires a flat coverage map keyed by those strings; generic
    # nested WSTG category placeholders make every initialized engagement fail
    # schema validation before the agent can begin testing.
    scope = yaml.safe_load(scope_yaml.read_text(encoding="utf-8")) or {}
    obligations = [
        str(item).strip()
        for item in ((scope.get("engagement") or {}).get("coverage_obligations") or [])
        if str(item).strip()
    ]
    coverage = {
        "coverage": {
            obligation.lower(): {"status": "pending", "evidence_or_reason": ""}
            for obligation in obligations
        }
    }
    (eng_dir / "state" / "coverage-matrix.yaml").write_text(
        yaml.safe_dump(coverage, sort_keys=False), encoding="utf-8"
    )

    hist_md = eng_dir / "state" / "history.md"
    hist_md.write_text(
        "# Command History Log\n# Format: TIMESTAMP | PHASE | TARGET | CMD\n",
        encoding="utf-8",
    )
