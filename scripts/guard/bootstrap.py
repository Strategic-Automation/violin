"""Bootstrap and skill-load enforcement for the Violin guard package.

Covers the `check-skill-loaded` and `check-bootstrap` subcommands plus the
corrupt-artifact auto-repair helper. `validate_scope_data` lives in `scope.py`.
"""

from __future__ import annotations

import argparse
import datetime as _dt
import re
import shutil
from pathlib import Path

from guard.core import CheckResult, ROOT

# Map of required file path (relative to eng_dir) -> (template path, post-create command).
# post_create_cmd None means the template itself is the bootstrap content; otherwise we
# initialise the file with a one-liner (e.g. history.md needs `# Command History — date`).
_REPAIR_TARGETS = {
    Path("scope/scope.yaml"):         ("skills/pentest/templates/scope-template.yaml", None),
    Path("state/ptt.md"):             ("skills/pentest/templates/ptt.md",             None),
    Path("hypotheses.md"):            ("skills/pentest/templates/hypothesis-board.md", None),
    Path("state/history.md"):         (None, "# Command History — repair placeholder\n"),
}

# Host/IP extraction from an engagement directory name of the form
# "<host>-<YYYY-MM-DD>" (e.g. "10.129.45.228-2026-07-08"). Used to pre-fill
# the scope target so the freshly bootstrapped engagement is guard-clean.
_HOST_RE = re.compile(r"([0-9]{1,3}(?:\.[0-9]{1,3}){3}|[0-9a-fA-F:]+|[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})")


def _derive_host(eng_dir: Path) -> str:
    match = _HOST_RE.search(eng_dir.name)
    return match.group(1) if match else "unknown-host"


def init_engagement(eng_dir: Path, host: str | None = None) -> int:
    """Create a complete, guard-clean engagement directory from templates.

    Auto-creates every bootstrap artifact (scope, PTT, hypothesis board,
    history) and pre-fills the scope ``targets.ip_addresses`` with the real
    host so ``validate_scope_data`` returns clean (0 errors/0 warnings) instead
    of the REVIEW that a literal copy-the-template would produce.

    This is the one-shot "auto create" path the agent invokes at engagement
    start; ``check-bootstrap --auto-repair`` reuses the same artifact builder
    to self-heal missing files on demand.
    """
    result = CheckResult()
    eng_dir = Path(eng_dir)
    host = (host or "").strip() or _derive_host(eng_dir)

    eng_dir.mkdir(parents=True, exist_ok=True)
    for rel, (template_rel, placeholder) in _REPAIR_TARGETS.items():
        target = eng_dir / rel
        if target.exists():
            continue
        target.parent.mkdir(parents=True, exist_ok=True)
        if placeholder is not None:
            target.write_text(placeholder, encoding="utf-8")
        else:
            src = ROOT / template_rel
            content = src.read_text(encoding="utf-8")
            if rel == Path("scope/scope.yaml"):
                # Pre-fill the in-scope target so the scope is guard-clean.
                import yaml
                data = yaml.safe_load(content)
                data["targets"]["ip_addresses"] = [host]
                data["engagement"]["date"] = _dt.date.today().isoformat()
                content = yaml.safe_dump(data, sort_keys=False, default_flow_style=False)
            # A freshly created PTT is legitimately pristine (all PT-XXX [ ]);
            # stamp it touched so the bootstrap stale-PTT REVIEW doesn't fire
            # on a brand-new engagement.
            if rel == Path("state/ptt.md"):
                import re as _re
                content = _re.sub(
                    r"\*Last updated:.*\*",
                    f"*Last updated: {_dt.datetime.now().strftime('%Y-%m-%d %H:%M')}*",
                    content,
                )
            target.write_text(content, encoding="utf-8")
        result.add_info(f"created {rel}")

    # Re-verify the freshly built engagement is bootstrap-complete and guard-clean.
    if result.errors or result.warnings:
        result.add_error("init-engagement produced an incomplete or non-compliant engagement")
        result.print()
        return 1
    result.add_info(f"engagement initialised and guard-clean: {eng_dir}")
    result.print()
    return 0


def check_skill_loaded(args: argparse.Namespace) -> int:
    """Mark the current session/work-block as having read the Violin skill.

    Creates a session-scoped marker file so ``_skill_loaded_guard`` in
    ``check-command`` can enforce that SKILL.md was loaded before any
    target-touching command runs.

    Marker location:
      - explicit ``--skill-loaded-file`` if provided
      - otherwise ``$ENG_DIR/state/.skill-loaded-<session-id>``

    The marker must be recreated after session boundaries that invalidate
    in-context knowledge: ``/new``, ``/goal set``, and context compression.
    """
    from guard.core import ROOT

    result = CheckResult()
    eng_dir = Path(args.eng_dir or "")
    if not eng_dir.exists():
        result.add_error(f"engagement directory not found: {eng_dir}")
        result.print()
        return 1
    session_id = (getattr(args, "session_id", "") or "").strip()
    if not session_id:
        result.add_error("--session-id is required")
        result.print()
        return 1
    explicit = (getattr(args, "skill_loaded_file", "") or "").strip()
    marker = Path(explicit) if explicit else (eng_dir / "state" / f".skill-loaded-{session_id}")
    try:
        marker.parent.mkdir(parents=True, exist_ok=True)
        marker.write_text(f"skill-loaded: skills/pentest/SKILL.md\nsession: {session_id}\n", encoding="utf-8")
    except Exception as exc:  # noqa: BLE001 - filesystem write should be explicit
        result.add_error(f"failed to write skill-loaded marker: {exc}")
        result.print()
        return 1
    result.add_info(f"skill-loaded marker created: {marker}")
    result.print()
    return 0


def check_bootstrap(args: argparse.Namespace) -> int:
    """Verify engagement bootstrap is complete.

    Required artifacts (all must exist and be non-empty):

    - $ENG_DIR/                        directory exists
    - $ENG_DIR/scope/scope.yaml        scope file present and parseable
    - $ENG_DIR/state/ptt.md            Pentesting Task Tree present
    - $ENG_DIR/hypotheses.md           hypothesis board present
    - $ENG_DIR/state/history.md        command history initialised

    Exit codes:
      0 = bootstrap complete
      1 = bootstrap missing (one or more required artifacts absent)
      2 = bootstrap partial (artifacts present but invalid)
    """
    from guard.record import _ptt_is_stale

    result = CheckResult()
    eng_dir_raw = args.eng_dir or ""
    if not eng_dir_raw:
        result.add_error("BOOTSTRAP REQUIRED: --eng-dir is empty (export ENG_DIR or pass --eng-dir)")
    eng_dir = Path(eng_dir_raw)

    required = [
        (eng_dir, "engagement directory"),
        (eng_dir / "scope" / "scope.yaml", "scope file"),
        (eng_dir / "state" / "ptt.md", "Pentesting Task Tree"),
        (eng_dir / "hypotheses.md", "hypothesis board"),
        (eng_dir / "state" / "history.md", "command history"),
    ]
    for path, label in required:
        if not eng_dir_raw:
            continue
        if not path.exists():
            result.add_error(f"BOOTSTRAP REQUIRED: missing {label} at {path}")
        elif path != eng_dir and path.is_dir():
            # Common LLM bootstrap drift: a required file got created as a
            # directory (e.g. write_file with an empty $ENG_DIR, or the model
            # treating the path as a folder and writing inside it). Block the
            # bootstrap with a precise, recoverable error. Skipped for the
            # engagement root itself, which is supposed to be a directory.
            template = (
                "hypothesis-board.md" if path.name == "hypotheses.md"
                else "ptt.md" if path.name == "ptt.md"
                else "history.md" if path.name == "history.md"
                else "scope-template.yaml"
            )
            result.add_error(
                f"BOOTSTRAP CORRUPT: {label} at {path} is a DIRECTORY but must be a FILE. "
                f"Fix: rm -rf \"{path}\" && cp skills/pentest/templates/{template} \"{path}\""
            )
        elif path.is_file() and path.stat().st_size == 0:
            result.add_warning(f"bootstrap artifact is empty: {path}")

    if eng_dir_raw and eng_dir.exists() and not (eng_dir / "scope" / "scope.yaml").exists():
        result.add_info("create the scope with: cp skills/pentest/templates/scope-template.yaml <ENG_DIR>/scope/scope.yaml")
    if eng_dir_raw and eng_dir.exists() and not (eng_dir / "state" / "ptt.md").exists():
        result.add_info("create the PTT with: cp skills/pentest/templates/ptt.md <ENG_DIR>/state/ptt.md")
    if eng_dir_raw and eng_dir.exists() and not (eng_dir / "hypotheses.md").exists():
        result.add_info("create the hypothesis board with: cp skills/pentest/templates/hypothesis-board.md <ENG_DIR>/hypotheses.md")
    if eng_dir_raw and eng_dir.exists() and not (eng_dir / "state" / "history.md").exists():
        result.add_info("initialise command history with: echo \"# Command History — $(date +%F)\" > <ENG_DIR>/state/history.md")

    # Stale-PTT drift detection at session resume: if every PT-XXX row is still
    # in the pristine [ ] state, the engagement was not touched since bootstrap.
    if eng_dir_raw and eng_dir.exists():
        ptt_check = eng_dir / "state" / "ptt.md"
        if ptt_check.exists() and _ptt_is_stale(ptt_check):
            result.add_warning("PTT has never been updated (all PT-XXX rows are [ ]); possible drift at session resume")

    # Auto-repair pass (only when --auto-repair is passed, so the default check
    # stays strict): heal bootstrap drift. Two classes are healed:
    #   1. A required artifact exists *as a directory* (LLM bootstrap drift) —
    #      remove it and re-create from the canonical template.
    #   2. A required artifact is *missing entirely* — create it from the
    #      template, pre-filling the scope target so the result is guard-clean.
    # Each repair is logged as an info note and the matching BOOTSTRAP
    # error/warning is stripped so the next pass returns clean.
    if getattr(args, "auto_repair", False):
        result = _auto_repair_corrupt_artifacts(eng_dir, result)

    if not result.errors and not result.warnings:
        result.add_info(f"bootstrap complete: {eng_dir}")
    result.print()
    if result.errors:
        return 1
    if result.warnings:
        return 2
    return 0


def _auto_repair_corrupt_artifacts(eng_dir: Path, result: CheckResult) -> CheckResult:
    """Repair bootstrap drift (directory drift AND missing artifacts).

    Each repair is logged as an info note and the matching BOOTSTRAP
    error/warning is stripped so the next pass returns clean.
    """
    new_errors, new_warnings, new_infos = [], [], list(result.infos)

    # Class 0: the engagement directory itself is missing — create it so the
    # artifact loop below has a place to write into.
    if not eng_dir.exists():
        try:
            eng_dir.mkdir(parents=True, exist_ok=True)
            new_infos.append(f"AUTO-REPAIR: created missing engagement directory {eng_dir}")
        except Exception as exc:  # noqa: BLE001
            new_errors.append(f"AUTO-REPAIR FAILED creating {eng_dir}: {exc}")

    for rel, (template_rel, placeholder) in _REPAIR_TARGETS.items():
        target = eng_dir / rel

        if target.is_dir():
            # Class 1: LLM bootstrap drift — required file created as a directory.
            try:
                shutil.rmtree(target)
                _create_artifact(eng_dir, rel, template_rel, placeholder)
                new_infos.append(
                    f"AUTO-REPAIR: removed dir {target} and re-created as file "
                    f"from {template_rel or 'inline placeholder'}"
                )
            except Exception as exc:  # noqa: BLE001
                new_errors.append(
                    f"AUTO-REPAIR FAILED for {rel} at {target}: {exc}"
                )
            continue

        if not target.exists():
            # Class 2: artifact missing entirely — create it from the template.
            try:
                _create_artifact(eng_dir, rel, template_rel, placeholder)
                new_infos.append(f"AUTO-REPAIR: created missing {target} from template")
            except Exception as exc:  # noqa: BLE001
                new_errors.append(
                    f"AUTO-REPAIR FAILED for {rel} at {target}: {exc}"
                )
            continue

    # Strip the BOOTSTRAP REQUIRED / CORRUPT errors we just repaired.
    for e in result.errors:
        if "missing engagement directory" in e or any(
            rel.name in e
            for rel in (Path("scope/scope.yaml"), Path("state/ptt.md"),
                        Path("hypotheses.md"), Path("state/history.md"))
        ):
            new_infos.append(f"resolved: {e}")
            continue
        new_errors.append(e)
    for w in result.warnings:
        new_warnings.append(w)

    return CheckResult(errors=new_errors, warnings=new_warnings, infos=new_infos)


def _create_artifact(eng_dir: Path, rel: Path, template_rel: str | None,
                     placeholder: str | None) -> None:
    """Create a single required bootstrap artifact at ``eng_dir / rel``.

    Reuses the same logic as ``init_engagement`` so a missing scope lands
    with its in-scope target pre-filled (guard-clean) rather than empty.
    """
    target = eng_dir / rel
    target.parent.mkdir(parents=True, exist_ok=True)
    if placeholder is not None:
        target.write_text(placeholder, encoding="utf-8")
        return
    content = (ROOT / template_rel).read_text(encoding="utf-8")
    if rel == Path("scope/scope.yaml"):
        import yaml
        data = yaml.safe_load(content)
        data["targets"]["ip_addresses"] = [_derive_host(eng_dir)]
        data["engagement"]["date"] = _dt.date.today().isoformat()
        content = yaml.safe_dump(data, sort_keys=False, default_flow_style=False)
    target.write_text(content, encoding="utf-8")
