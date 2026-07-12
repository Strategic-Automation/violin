#!/usr/bin/env python3
"""Hypothesis-driven recon evidence guard.

Subcommands:
- record-hypothesis  Append or update a service-level hypothesis entry.
- check-hypothesis    Verify at least one researched or verified hypothesis
                      exists for a given service/port combination.

This guard is intentionally lightweight and file-based:
state lives in `$ENG_DIR/hypotheses.md`, with one H-XXX block per theory.
"""

from __future__ import annotations

import argparse
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]

# Share CheckResult with the guard package (single source of truth).
if str(ROOT / "scripts") not in sys.path:
    sys.path.insert(0, str(ROOT / "scripts"))
from guard.core import CheckResult  # noqa: E402

_HYPOTHESIS_HEADING_RE = re.compile(r"^### (H-\d+):", re.MULTILINE)
_FIELD_RE = re.compile(r"^- \*\*(.+?):\*\*\s*(.*)$", re.MULTILINE)


@dataclass
class Hypothesis:
    id: str
    status: str = "candidate"
    phase: str = ""
    service: str = ""
    target: str = ""
    vuln_class: str = ""
    rationale: str = ""
    evidence: str = ""
    updated: str = ""


def _parse_hypotheses(path: Path) -> list[Hypothesis]:
    text = path.read_text(encoding="utf-8")
    hypotheses: list[Hypothesis] = []
    sections = list(_HYPOTHESIS_HEADING_RE.split(text))
    for idx in range(1, len(sections), 2):
        hyp_id = sections[idx].strip()
        body = sections[idx + 1]
        fields: dict[str, str] = {}
        for name, value in _FIELD_RE.findall(body):
            fields[name.strip().lower()] = value.strip()
        hypotheses.append(
            Hypothesis(
                id=hyp_id,
                status=fields.get("status", "candidate").lower(),
                phase=fields.get("phase", "").lower(),
                service=fields.get("service", "").lower(),
                target=fields.get("target", "").lower(),
                vuln_class=fields.get("vuln class", "").lower(),
                rationale=fields.get("rationale", "").lower(),
                evidence=fields.get("evidence", ""),
                updated=fields.get("updated", ""),
            )
        )
    return hypotheses


# CheckResult is imported from guard.core (single source of truth) — see above.


def _next_id(hypotheses: list[Hypothesis]) -> str:
    max_id = 0
    for hypothesis in hypotheses:
        match = re.fullmatch(r"H-(\d+)", hypothesis.id.upper())
        if match:
            max_id = max(max_id, int(match.group(1)))
    return f"H-{max_id + 1:03d}"


def _status_value(status: str) -> str:
    normalized = status.strip().lower()
    allowed = {"candidate", "researching", "verified", "rejected"}
    if normalized not in allowed:
        raise ValueError(f"status must be one of {sorted(allowed)}, got: {status!r}")
    return normalized.capitalize()


def record_hypothesis(args: argparse.Namespace) -> int:
    result = CheckResult()
    eng_dir = Path(args.eng_dir or "")
    hypotheses_path = eng_dir / "hypotheses.md"

    if not eng_dir.exists():
        result.add_error(f"engagement directory not found: {eng_dir}")
        result.print()
        return 1
    if not hypotheses_path.exists():
        result.add_error(f"hypotheses.md not found: {hypotheses_path}")
        result.add_info("bootstrap with: cp skills/pentest/templates/hypothesis-board.md \"$ENG_DIR/hypotheses.md\"")
        result.print()
        return 1

    service = (args.service or "").strip()
    port = (args.port or "").strip()
    if not service or not port:
        result.add_error("--service and --port are required")
        result.print()
        return 1

    title = (args.title or "").strip() or f"Unnamed hypothesis for {service}:{port}"
    try:
        status_value = _status_value(args.status or "candidate")
    except ValueError as exc:
        result.add_error(str(exc))
        result.print()
        return 1
    status_value = status_value.capitalize()

    # Resolve the real host string. `--target` wins; otherwise derive the host
    # from the engagement directory name (expected "<host>-<YYYY-MM-DD>") so we
    # never record the literal placeholder "<target>", which would never match
    # a real command's host in `_hypothesis_guard`.
    target_host = (args.target or "").strip()
    if not target_host:
        import re as _re
        _m = _re.search(r"([0-9]{1,3}(?:\.[0-9]{1,3}){3}|[0-9a-fA-F:]+|[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})", eng_dir.name)
        target_host = _m.group(1) if _m else "unknown-host"

    hypotheses = _parse_hypotheses(hypotheses_path)
    update_id = (args.id or "").strip().upper()
    target_hyp = None
    target_index = None
    for idx, hypothesis in enumerate(hypotheses):
        if hypothesis.id.upper() == update_id:
            target_hyp = hypothesis
            target_index = idx
            break

    fields = {
        "status": status_value,
        "phase": args.phase or target_hyp.phase if target_hyp else (args.phase or "RECON"),
        "service": service,
        "target": f"{target_host}:{port}",
        "vuln class": args.vuln_class or target_hyp.vuln_class if target_hyp else "",
        "rationale": args.rationale or target_hyp.rationale if target_hyp else "",
        "evidence": args.evidence or target_hyp.evidence if target_hyp else "",
        "updated": args.updated or "",
    }

    if target_hyp is None:
        new_hyp_id = _next_id(hypotheses)
        block = (
            f"\n### {new_hyp_id}: {title}\n"
            f"- **Status:** {fields['status']}\n"
            f"- **Phase:** {fields['phase']}\n"
            f"- **Service:** {service}\n"
            f"- **Target:** {fields['target']}\n"
            f"- **Vuln class:** {fields['vuln class']}\n"
            f"- **Rationale:** {fields['rationale']}\n"
            f"- **Evidence:** `{fields['evidence']}`\n"
            f"- **Next step:** <research or validate>\n"
            f"- **Linked findings:** <none yet>\n"
            f"- **Updated:** {fields['updated'] or '<YYYY-MM-DD HH:MM>'}\n"
        )
        with hypotheses_path.open("a", encoding="utf-8") as handle:
            handle.write(block)
        result.add_info(f"created hypothesis {new_hyp_id}: {service}:{port} — {title}")
    else:
        text = hypotheses_path.read_text(encoding="utf-8")
        pattern = re.compile(
            r"### " + re.escape(target_hyp.id) + r":.+?(?=\n### |\Z)",
            re.DOTALL,
        )
        replacement = (
            f"### {target_hyp.id}: {title}\n"
            f"- **Status:** {fields['status']}\n"
            f"- **Phase:** {fields['phase']}\n"
            f"- **Service:** {fields['service']}\n"
            f"- **Target:** {fields['target']}\n"
            f"- **Vuln class:** {fields['vuln class']}\n"
            f"- **Rationale:** {fields['rationale']}\n"
            f"- **Evidence:** `{fields['evidence']}`\n"
            f"- **Next step:** <update after research>\n"
            f"- **Linked findings:** <none yet>\n"
            f"- **Updated:** {fields['updated'] or '<YYYY-MM-DD HH:MM>'}\n"
        )
        new_text, subs = pattern.subn(replacement, text)
        if subs != 1:
            result.add_error(f"failed to update hypothesis block {target_hyp.id}; match count={subs}")
            result.print()
            return 1
        hypotheses_path.write_text(new_text, encoding="utf-8")
        result.add_info(f"updated hypothesis {target_hyp.id}: {service}:{port} → {status_value}")

    result.print()
    return 0


def check_hypothesis(args: argparse.Namespace) -> int:
    result = CheckResult()
    eng_dir = Path(args.eng_dir or "")
    hypotheses_path = eng_dir / "hypotheses.md"

    if not eng_dir.exists():
        result.add_error(f"engagement directory not found: {eng_dir}")
        result.print()
        return 1
    if not hypotheses_path.exists():
        result.add_error(f"hypotheses.md not found: {hypotheses_path}")
        result.add_info("bootstrap with: cp skills/pentest/templates/hypothesis-board.md \"$ENG_DIR/hypotheses.md\"")
        result.print()
        return 1

    service = (args.service or "").strip().lower()
    port = (args.port or "").strip()
    if not service or not port:
        result.add_error("--service and --port are required")
        result.print()
        return 1

    try:
        hypotheses = _parse_hypotheses(hypotheses_path)
    except Exception as exc:  # noqa: BLE001 - file read/parse failure should be explicit
        result.add_error(f"failed to parse hypotheses.md: {exc}")
        result.print()
        return 1

    requires_research = getattr(args, "require_research", False)
    verified = [
        hypothesis
        for hypothesis in hypotheses
        if hypothesis.service == service
        and hypothesis.target.endswith(f":{port}")
        and hypothesis.status in {"researching", "verified"}
    ]

    if not verified:
        result.add_error(
            f"HYPOTHESIS REQUIRED: no researching/verified hypothesis for {service}:{port} in {hypotheses_path}"
        )
        result.add_info(
            "run: python scripts/hypothesis_guard.py record-hypothesis "
            f"--eng-dir \"$ENG_DIR\" --service {service} --port {port} "
            "--status researching --title \"<short title>\" --rationale \"<why>\""
        )
        result.print()
        return 1

    if requires_research and all(hypothesis.status != "verified" for hypothesis in verified):
        result.add_warning(f"hypothesis for {service}:{port} is only researching; verified entry required before exploitation")

    result.add_info(
        f"hypothesis ok: {service}:{port} -> "
        + ", ".join(f"{hypothesis.id} ({hypothesis.status})" for hypothesis in verified)
    )
    result.print()
    return result.exit_code()


def main() -> int:
    parser = argparse.ArgumentParser(description="Hypothesis evidence guard")
    subparsers = parser.add_subparsers(dest="command_name", required=True)

    record_parser = subparsers.add_parser("record-hypothesis", help="append or update a hypothesis entry in hypotheses.md")
    record_parser.add_argument("--eng-dir", required=True, help="engagement directory")
    record_parser.add_argument("--service", required=True, help="service name (e.g. SMB)")
    record_parser.add_argument("--port", required=True, help="port number (e.g. 445)")
    record_parser.add_argument("--id", default="", help="existing H-XXX id to update in place")
    record_parser.add_argument("--title", default="", help="short hypothesis title")
    record_parser.add_argument("--status", default="candidate", help="candidate|researching|verified|rejected")
    record_parser.add_argument("--phase", default="RECON", help="phase tag for this hypothesis")
    record_parser.add_argument("--target", default="", help="host/IP this hypothesis targets (e.g. 10.1.2.3). If omitted, derived from the engagement dir name. NEVER the literal '<target>'.")
    record_parser.add_argument("--vuln-class", default="", help="vulnerability class (e.g. CVE-2021-44142)")
    record_parser.add_argument("--rationale", default="", help="why this service is interesting")
    record_parser.add_argument("--evidence", default="", help="path to supporting evidence")
    record_parser.add_argument("--updated", default="", help="override updated timestamp")
    record_parser.set_defaults(func=record_hypothesis)

    check_parser = subparsers.add_parser("check-hypothesis", help="verify researched/verified hypotheses exist for a service:port")
    check_parser.add_argument("--eng-dir", required=True, help="engagement directory")
    check_parser.add_argument("--service", required=True, help="service name")
    check_parser.add_argument("--port", required=True, help="port number")
    check_parser.add_argument("--require-research", action="store_true", help="warn when only researching is present")
    check_parser.set_defaults(func=check_hypothesis)

    args = parser.parse_args()
    try:
        return args.func(args)
    except Exception as exc:  # noqa: BLE001 - CLI should fail clearly
        print(f"BLOCK: {exc}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
