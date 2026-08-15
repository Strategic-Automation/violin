"""Release gate checks for the Violin plugin.

The checker is a REAL gate: it runs an isolated plugin import, compares the
manifest's provides_tools against the tools actually registered, and (unless
disabled) shells out to ruff and pytest. Failures surface as errors and cause
a non-zero exit code — so CI cannot pass a broken tree.

Heavy checks (ruff/pytest) are gated behind VIOLIN_CHECK_RELEASE_SKIP_HEAVY=1
(default: run them).
"""

from __future__ import annotations

import importlib.util
import os
import re
import shutil
import subprocess
import sys
import tempfile
import tomllib
from dataclasses import dataclass
from pathlib import Path

from .results import GuardResult
from .skill_policy import catalog_snapshot, validate_catalog

__all__ = [
    "GuardResult",
    "ReleaseCheckResult",
    "check_release",
    "main",
    "resolve_reference",
]


def _project_python(repo_root: Path) -> str:
    """Prefer the repository virtualenv when a profile runtime invokes the CLI."""

    candidates = (
        repo_root / ".venv" / "Scripts" / "python.exe",
        repo_root / ".venv" / "bin" / "python",
    )
    for candidate in candidates:
        if candidate.exists():
            return str(candidate)
    return sys.executable


@dataclass
class ReleaseCheckResult(GuardResult):
    pass


def _plugin_root() -> Path:
    # plugins/violin_guard/release.py -> plugins/violin_guard
    return Path(__file__).resolve().parent


def _pytest_basetemp(repo_path: Path) -> str:
    """Create pytest's private temp directory in the ignored engagement tree."""

    engagement_root = repo_path / "engagements"
    engagement_root.mkdir(parents=True, exist_ok=True)
    return tempfile.mkdtemp(prefix=".pytest-release-", dir=engagement_root)


def resolve_reference(source: Path, reference: str) -> Path:
    """Resolve a pentest skill reference from the skill package root."""
    source = source.resolve()
    for parent in (source.parent, *source.parents):
        if parent.name == "pentest" and parent.parent.name == "skills":
            return (parent / reference).resolve()
    raise ValueError(f"source is not inside skills/pentest: {source}")


def _check_manifest_and_changelog(root: Path, result: ReleaseCheckResult) -> list[str]:
    """Require exact SemVer equality across every published version surface."""
    plugin_yaml = root / "plugin.yaml"
    provides_tools: list[str] = []
    versions: dict[str, str] = {}
    if plugin_yaml.exists():
        import yaml

        data = yaml.safe_load(plugin_yaml.read_text(encoding="utf-8"))
        version = str(data.get("version", "0.0.0"))
        versions["plugin manifest"] = version
        provides_tools = list(data.get("provides_tools", []) or [])
        if not re.fullmatch(r"\d+\.\d+\.\d+", version):
            result.add_error(f"plugin.yaml version '{version}' is not a valid semver")
    else:
        result.add_error("plugin.yaml not found")

    repo = root.parent.parent
    pyproject = repo / "pyproject.toml"
    if pyproject.exists():
        project = tomllib.loads(pyproject.read_text(encoding="utf-8"))["project"]
        versions["project"] = str(project.get("version", ""))
        dependencies = [str(value).lower() for value in project.get("dependencies", [])]
        if not any(value.startswith("pyyaml") for value in dependencies):
            result.add_error("PyYAML must be a runtime project dependency")
        else:
            result.add_info("PyYAML is declared as a runtime dependency")
    else:
        result.add_error("pyproject.toml not found")

    distribution = repo / "distribution.yaml"
    if distribution.exists():
        import yaml

        versions["distribution"] = str(
            yaml.safe_load(distribution.read_text(encoding="utf-8")).get("version", "")
        )
    else:
        result.add_error("distribution.yaml not found")

    changelog = repo / "CHANGELOG.md"
    if changelog.exists():
        match = re.search(
            r"(?m)^## (\d+\.\d+\.\d+)(?: \(Unreleased\))?\s*$",
            changelog.read_text(encoding="utf-8"),
        )
        if match:
            versions["changelog"] = match.group(1)
        else:
            result.add_error("CHANGELOG.md has no top SemVer entry")
    else:
        result.add_error("CHANGELOG.md not found")

    invalid = {
        name: value for name, value in versions.items() if not re.fullmatch(r"\d+\.\d+\.\d+", value)
    }
    for name, value in invalid.items():
        result.add_error(f"{name} version '{value}' is not exact SemVer")
    if versions and len(set(versions.values())) != 1:
        result.add_error(
            "version mismatch: " + ", ".join(f"{name}={value}" for name, value in versions.items())
        )
    elif versions:
        result.add_info(f"all version surfaces match {next(iter(versions.values()))}")

    return provides_tools


def _check_isolated_import_and_tools(
    root: Path, provides_tools: list[str], result: ReleaseCheckResult
) -> None:
    """Verify isolated plugin import and manifest vs registered tools match."""
    module_name = "violin_guard_release_check"
    old_module = sys.modules.get(module_name)
    mod = None
    try:
        sys.path.insert(0, str(root.parent))
        spec = importlib.util.spec_from_file_location(
            module_name,
            root / "__init__.py",
            submodule_search_locations=[str(root)],
        )
        if spec is None or spec.loader is None:
            raise ImportError("could not build plugin import specification")
        mod = importlib.util.module_from_spec(spec)
        sys.modules[module_name] = mod
        spec.loader.exec_module(mod)
        result.add_info("isolated plugin import OK")
    except Exception as exc:  # noqa: BLE001
        result.add_error(f"plugin import failed: {type(exc).__name__}: {exc}")
    finally:
        sys.path.pop(0)
        if old_module is None:
            sys.modules.pop(module_name, None)
        else:
            sys.modules[module_name] = old_module

    if mod is not None:
        registered = sorted(getattr(mod, "REGISTERED_TOOLS", []) or [])
        if not registered:
            result.add_warning("plugin exposes no REGISTERED_TOOLS list")
        elif sorted(provides_tools) != registered:
            result.add_error(
                "provides_tools mismatch: manifest="
                f"{sorted(provides_tools)} registered={registered}"
            )
        else:
            result.add_info("provides_tools matches registered tools")
        definitions = list(getattr(mod, "TOOL_DEFINITIONS", []) or [])
        for definition in definitions:
            expected = mod.schemas.to_tool_schema(definition.model)["parameters"]
            if definition.schema.get("parameters") != expected:
                result.add_error(f"tool schema drift for {definition.name}")
        if len(definitions) == len(registered):
            result.add_info("tool registry models and exported schemas are consistent")


def _check_skill_snapshot(root: Path, result: ReleaseCheckResult) -> None:
    """Verify checked-in external-skill dependency manifest against approved catalog."""
    snapshot_path = root.parent.parent / "skills.snapshot.json"
    catalog_errors = validate_catalog()
    if catalog_errors:
        result.errors.extend(catalog_errors)
    elif not snapshot_path.exists():
        result.add_error("skills.snapshot.json not found")
    else:
        import json

        try:
            checked_in = json.loads(snapshot_path.read_text(encoding="utf-8"))
            expected = catalog_snapshot(root.parent.parent)
            for entry in expected["skills"]:
                entry.pop("path", None)
            if checked_in != expected:
                result.add_error("skills.snapshot.json does not match the approved skill catalog")
            else:
                result.add_info("external skill dependency snapshot matches catalog")
        except (OSError, json.JSONDecodeError) as exc:
            result.add_error(f"skills.snapshot.json is invalid: {exc}")


def _check_heavy_linter_and_tests(root: Path, result: ReleaseCheckResult) -> None:
    """Execute ruff and pytest heavy release gates unless opted out via env."""
    if os.environ.get("VIOLIN_CHECK_RELEASE_SKIP_HEAVY") == "1":
        result.add_info("heavy checks skipped (VIOLIN_CHECK_RELEASE_SKIP_HEAVY=1)")
        return

    repo_path = root.parent.parent
    repo_root = str(repo_path)
    python = _project_python(repo_path)
    try:
        ruff = subprocess.run(
            [python, "-m", "ruff", "check", "."],
            cwd=repo_root,
            capture_output=True,
            text=True,
        )
        if ruff.returncode != 0:
            result.add_error("ruff check failed:\n" + (ruff.stdout or ruff.stderr).strip()[:2000])
        else:
            result.add_info("ruff check passed")
    except FileNotFoundError:
        result.add_warning("ruff not installed; skipped")

    basetemp = _pytest_basetemp(repo_path)
    try:
        pytest = subprocess.run(
            [
                python,
                "-m",
                "pytest",
                "-q",
                "-p",
                "no:cacheprovider",
                "--basetemp",
                basetemp,
            ],
            cwd=repo_root,
            capture_output=True,
            text=True,
        )
        if pytest.returncode != 0:
            result.add_error(
                "test suite failed:\n" + (pytest.stdout or pytest.stderr).strip()[:2000]
            )
        else:
            result.add_info("test suite passed")
    except FileNotFoundError:
        result.add_warning("pytest not installed; skipped")
    finally:
        shutil.rmtree(basetemp, ignore_errors=True)


def _check_stale_skill_docs(root: Path, result: ReleaseCheckResult) -> None:
    """Scan skill documentation for stale or deprecated guard surface references."""
    profile_root = root.parent.parent
    skills_root = profile_root / "skills"
    forbidden = {
        "scripts/guard/": "removed legacy guard package",
        "hypothesis_guard.py": "removed hypothesis wrapper",
        "session_search": "unavailable session-search tool",
        "violin_record_history": "removed executor-owned history tool",
        "violin_message_tick": "removed model-visible message tool",
        "violin_guard.py close": "nonexistent close subcommand",
        "check-closeout": "nonexistent closeout subcommand",
        "sync-clear": "nonexistent sync-clear subcommand",
        "validate_scope_data": "private legacy scope validator",
    }
    if not skills_root.exists():
        return

    docs = [*skills_root.rglob("*.md"), *skills_root.rglob("*.yaml")]
    for doc in docs:
        try:
            text = doc.read_text(encoding="utf-8")
        except Exception:
            continue
        for token, reason in forbidden.items():
            if token in text:
                result.add_error(
                    f"stale skill reference in {doc.relative_to(profile_root)}: "
                    f"{token!r} ({reason})"
                )
    if not any("stale skill reference" in e for e in result.errors):
        result.add_info("skill documentation matches the current guard surface")


def _check_active_documentation_contracts(root: Path, result: ReleaseCheckResult) -> None:
    repo = root.parent.parent
    docs = [repo / "README.md", *sorted((repo / "skills").rglob("*.md"))]
    stale_credit = re.compile(
        r"(?:Recon|RECON):?\s*5|(?:Exploitation|EXPLOITATION):?\s*10", re.IGNORECASE
    )
    stale_findings = re.compile(r"\|\s*Findings\s*\|[^\n]*findings\.yaml", re.IGNORECASE)
    for path in docs:
        text = path.read_text(encoding="utf-8")
        if stale_credit.search(text):
            result.add_error(f"stale sync-credit contract in {path.relative_to(repo)}")
        if stale_findings.search(text):
            result.add_error(f"stale canonical-finding contract in {path.relative_to(repo)}")
    if not any("contract in" in error for error in result.errors):
        result.add_info("active documentation contracts are current")


def check_release() -> ReleaseCheckResult:
    """Run all release gate checks. This is a REAL gate — failures add errors
    and cause a non-zero exit code (see CLI cmd_check_release)."""
    result = ReleaseCheckResult()
    root = _plugin_root()

    provides_tools = _check_manifest_and_changelog(root, result)
    _check_isolated_import_and_tools(root, provides_tools, result)
    _check_skill_snapshot(root, result)
    _check_heavy_linter_and_tests(root, result)

    tests_dir = root.parent.parent / "tests"
    if tests_dir.exists():
        result.add_info(f"tests directory found: {tests_dir}")
    else:
        result.add_warning("tests directory not found")

    _check_stale_skill_docs(root, result)
    _check_active_documentation_contracts(root, result)
    return result


def main() -> int:
    """Print release diagnostics and return nonzero only when errors exist."""
    result = check_release()
    for item in result.errors:
        print(f"ERROR: {item}")
    for item in result.warnings:
        print(f"WARN: {item}")
    for item in result.infos:
        print(f"OK: {item}")
    return 1 if result.errors else 0


if __name__ == "__main__":
    sys.exit(main())
