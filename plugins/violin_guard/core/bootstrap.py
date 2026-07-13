"""Bootstrap & auto-repair for engagement directories.

Creates guard-clean artifacts from templates. No subprocess calls.
"""

from __future__ import annotations

import re
import shutil
from datetime import date, datetime
from pathlib import Path

import yaml

__all__ = [
    "init_engagement",
    "check_bootstrap",
    "BootstrapResult",
]

_HOST_RE = re.compile(r"([0-9]{1,3}(?:\.[0-9]{1,3}){3}|[0-9a-fA-F:]+|[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})")

_REPAIR_TEMPLATES = {
    Path("scope/scope.yaml"): ("skills/pentest/templates/scope-template.yaml", None),
    Path("state/ptt.md"): ("skills/pentest/templates/ptt.md", None),
    Path("hypotheses.md"): ("skills/pentest/templates/hypothesis-board.md", None),
    Path("state/history.md"): (None, "# Command History — repair placeholder\n"),
}


class BootstrapResult:
    def __init__(
        self,
        errors: list[str] | None = None,
        warnings: list[str] | None = None,
        infos: list[str] | None = None,
    ):
        self.errors = errors or []
        self.warnings = warnings or []
        self.infos = infos or []

    def add_error(self, msg: str) -> None:
        self.errors.append(msg)

    def add_warning(self, msg: str) -> None:
        self.warnings.append(msg)

    def add_info(self, msg: str) -> None:
        self.infos.append(msg)

    def exit_code(self) -> int:
        if self.errors:
            return 1
        if self.warnings:
            return 2
        return 0

    def __int__(self) -> int:
        return self.exit_code()

    def print(self) -> None:
        for e in self.errors:
            print(f"ERROR: {e}")
        for w in self.warnings:
            print(f"WARNING: {w}")
        for i in self.infos:
            print(f"INFO: {i}")


def _derive_host(eng_dir: Path) -> str:
    match = _HOST_RE.search(eng_dir.name)
    return match.group(1) if match else "unknown-host"


def _profile_root() -> Path:
    """Profile root = plugins/violin_guard/../../.."""
    return Path(__file__).resolve().parents[3]


def _create_artifact(
    eng_dir: Path,
    rel: Path,
    template_rel: str | None,
    placeholder: str | None,
    host: str | None = None,
    ctf: bool = False,
) -> None:
    target = eng_dir / rel
    target.parent.mkdir(parents=True, exist_ok=True)
    if placeholder is not None:
        target.write_text(placeholder, encoding="utf-8")
        return
    assert template_rel is not None
    src = _profile_root() / template_rel
    content = src.read_text(encoding="utf-8")
    if rel == Path("scope/scope.yaml"):
        data = yaml.safe_load(content)
        data["targets"]["ip_addresses"] = [host or _derive_host(eng_dir)]
        data["engagement"]["date"] = date.today().isoformat()
        content = yaml.safe_dump(data, sort_keys=False, default_flow_style=False)
    if rel == Path("state/ptt.md"):
        content = re.sub(
            r"\*Last updated:.*\*",
            f"*Last updated: {datetime.now().strftime('%Y-%m-%d %H:%M')}*",
            content,
        )
        if ctf:
            content = _ctf_ptt(host or _derive_host(eng_dir))
    target.write_text(content, encoding="utf-8")


def _ctf_ptt(host: str) -> str:
    today = date.today().isoformat()
    return f"""# CTF Task Tree — {host} {today}

*Last updated: {datetime.now().strftime("%Y-%m-%d %H:%M")}*

## Phase: RECON
| ID | Status | Task | Evidence / Notes |
|----|--------|------|------------------|
| PT-CTF-001 | [~] | Enumerate services and attack surface | evidence/recon/ |

## Phase: EXPLOITATION
| ID | Status | Task | Evidence / Notes |
|----|--------|------|------------------|
| PT-CTF-002 | [ ] | Validate an in-scope foothold | evidence/exploitation/ |

## Phase: PRIVESC
| ID | Status | Task | Evidence / Notes |
|----|--------|------|------------------|
| PT-CTF-003 | [ ] | Enumerate and validate privilege escalation | evidence/exploitation/ |

## Phase: FLAGS
| ID | Status | Task | Evidence / Notes |
|----|--------|------|------------------|
| PT-CTF-004 | [ ] | Capture user.txt and root.txt | evidence/flags/ |
"""


def _ctf_scope(host: str) -> dict:
    return {
        "targets": {"ip_addresses": [host], "in_scope_urls": []},
        "authorized_parties": ["lab owner (user)"],
        "rules_of_engagement": {
            "allowed_actions": [
                "host/port discovery",
                "banner grabbing",
                "version detection",
                "vulnerability scanning",
                "exploit validation (in-scope, non-destructive)",
                "privilege escalation",
                "flag capture (user.txt, root.txt)",
            ],
            "forbidden_actions": [],
        },
        "authorisation": {"confirmed": True, "confirmed_by": "user (HTB lab owner)"},
        "engagement": {
            "name": f"CTF {host}",
            "date": date.today().isoformat(),
            "type": "ctf",
            "mode": "standard-pentest",
            "depth": "black-box",
            "focus_areas": ["recon", "exploitation", "privilege-escalation", "flag-capture"],
        },
    }


def init_engagement(
    eng_dir: str | Path, host: str | None = None, *, ctf: bool = False, session_id: str = ""
) -> int:
    """Create a complete, guard-clean engagement directory from templates."""
    eng_dir = Path(eng_dir)
    result = BootstrapResult()
    host = (host or "").strip() or _derive_host(eng_dir)

    eng_dir.mkdir(parents=True, exist_ok=True)
    for rel, (template_rel, placeholder) in _REPAIR_TEMPLATES.items():
        target = eng_dir / rel
        if target.exists():
            continue
        _create_artifact(eng_dir, rel, template_rel, placeholder, host, ctf)
        result.add_info(f"created {rel}")

    if ctf:
        scope_path = eng_dir / "scope" / "scope.yaml"
        scope_path.write_text(yaml.safe_dump(_ctf_scope(host), sort_keys=False), encoding="utf-8")
        result.add_info("wrote CTF scope")
        if session_id:
            marker = eng_dir / "state" / f".skill-loaded-{session_id}"
            marker.write_text("skill-loaded: ctf bootstrap\n", encoding="utf-8")
            result.add_info(f"marked skill loaded for session {session_id}")

    if result.errors or result.warnings:
        result.add_error("init-engagement produced an incomplete or non-compliant engagement")
        result.print()
        return 1

    if ctf:
        result.add_info(f"engagement initialised and ready for authorised CTF work: {eng_dir}")
    else:
        result.add_info(
            f"engagement initialised; confirm scope authorisation before target work: {eng_dir}"
        )
    result.print()
    return 0


def check_bootstrap(
    eng_dir: str | Path,
    auto_repair: bool = False,
) -> BootstrapResult:
    """Verify engagement bootstrap is complete (and optionally auto-repair)."""
    result = BootstrapResult()
    eng_dir = Path(eng_dir)

    if not eng_dir.exists():
        result.add_error("BOOTSTRAP REQUIRED: engagement directory not found")
        return result

    required = [
        (eng_dir, "engagement directory"),
        (eng_dir / "scope" / "scope.yaml", "scope file"),
        (eng_dir / "state" / "ptt.md", "Pentesting Task Tree"),
        (eng_dir / "hypotheses.md", "hypothesis board"),
        (eng_dir / "state" / "history.md", "command history"),
    ]

    for path, label in required:
        if not path.exists():
            result.add_error(f"BOOTSTRAP REQUIRED: missing {label} at {path}")
        elif path != eng_dir and path.is_dir():
            template = (
                "hypothesis-board.md"
                if path.name == "hypotheses.md"
                else "ptt.md"
                if path.name == "ptt.md"
                else "history.md"
                if path.name == "history.md"
                else "scope-template.yaml"
            )
            result.add_error(
                f"BOOTSTRAP CORRUPT: {label} at {path} is a DIRECTORY but must be a FILE. "
                f'Fix: rm -rf "{path}" && cp skills/pentest/templates/{template} "{path}"'
            )
        elif path.is_file() and path.stat().st_size == 0:
            result.add_warning(f"bootstrap artifact is empty: {path}")

    if eng_dir.exists() and not (eng_dir / "scope" / "scope.yaml").exists():
        result.add_info(
            "create the scope with: cp skills/pentest/templates/scope-template.yaml <ENG_DIR>/scope/scope.yaml"
        )
    if eng_dir.exists() and not (eng_dir / "state" / "ptt.md").exists():
        result.add_info(
            "create the PTT with: cp skills/pentest/templates/ptt.md <ENG_DIR>/state/ptt.md"
        )
    if eng_dir.exists() and not (eng_dir / "hypotheses.md").exists():
        result.add_info(
            "create the hypothesis board with: cp skills/pentest/templates/hypothesis-board.md <ENG_DIR>/hypotheses.md"
        )
    if eng_dir.exists() and not (eng_dir / "state" / "history.md").exists():
        result.add_info(
            'initialise command history with: echo "# Command History — $(date +%F)" > <ENG_DIR>/state/history.md'
        )

    # Stale PTT detection
    if eng_dir.exists():
        ptt_check = eng_dir / "state" / "ptt.md"
        if ptt_check.exists() and _ptt_is_stale(ptt_check):
            result.add_warning(
                "PTT has never been updated (all PT-XXX rows are [ ]); possible drift at session resume"
            )

    if auto_repair:
        result = _auto_repair_corrupt_artifacts(eng_dir, result)

    if not result.errors and not result.warnings:
        result.add_info(f"bootstrap complete: {eng_dir}")

    return result


def _ptt_is_stale(ptt_path: Path) -> bool:
    """True if every PT-XXX row is still [ ] (pristine)."""
    content = ptt_path.read_text(encoding="utf-8")
    rows = [line for line in content.splitlines() if line.strip().startswith("| PT-")]
    return all("[ ]" in row for row in rows)


def _auto_repair_corrupt_artifacts(eng_dir: Path, result: BootstrapResult) -> BootstrapResult:
    """Repair directory drift and missing artifacts."""
    new_errors, new_warnings, new_infos = [], [], list(result.infos)

    if not eng_dir.exists():
        try:
            eng_dir.mkdir(parents=True, exist_ok=True)
            new_infos.append(f"AUTO-REPAIR: created missing engagement directory {eng_dir}")
        except Exception as exc:
            new_errors.append(f"AUTO-REPAIR FAILED creating {eng_dir}: {exc}")

    for rel, (template_rel, placeholder) in _REPAIR_TEMPLATES.items():
        target = eng_dir / rel

        if target.is_dir():
            try:
                shutil.rmtree(target)
                _create_artifact(eng_dir, rel, template_rel, placeholder)
                new_infos.append(
                    f"AUTO-REPAIR: removed dir {target} and re-created as file from "
                    f"{template_rel or 'inline placeholder'}"
                )
            except Exception as exc:
                new_errors.append(f"AUTO-REPAIR FAILED for {rel} at {target}: {exc}")
            continue

        if not target.exists():
            try:
                _create_artifact(eng_dir, rel, template_rel, placeholder)
                new_infos.append(f"AUTO-REPAIR: created missing {target} from template")
            except Exception as exc:
                new_errors.append(f"AUTO-REPAIR FAILED for {rel} at {target}: {exc}")
            continue

    # Strip repaired errors
    repaired_keys = {
        "missing engagement directory",
        "scope/scope.yaml",
        "state/ptt.md",
        "hypotheses.md",
        "state/history.md",
    }
    for e in result.errors:
        e_norm = e.replace("\\", "/")
        if any(key in e_norm for key in repaired_keys):
            new_infos.append(f"resolved: {e}")
            continue
        new_errors.append(e)

    for w in result.warnings:
        new_warnings.append(w)

    return BootstrapResult(errors=new_errors, warnings=new_warnings, infos=new_infos)
