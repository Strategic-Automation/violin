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
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

__all__ = [
    "ReleaseCheckResult",
    "StructureResult",
    "check_release",
    "validate_plugin_structure",
    "resolve_reference",
]


@dataclass
class ReleaseCheckResult:
    errors: list[str] = None
    warnings: list[str] = None
    infos: list[str] = None

    def __post_init__(self):
        if self.errors is None:
            self.errors = []
        if self.warnings is None:
            self.warnings = []
        if self.infos is None:
            self.infos = []

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


@dataclass
class StructureResult:
    errors: list[str] = None
    warnings: list[str] = None
    infos: list[str] = None

    def __post_init__(self):
        if self.errors is None:
            self.errors = []
        if self.warnings is None:
            self.warnings = []
        if self.infos is None:
            self.infos = []

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


def _plugin_root() -> Path:
    return Path(__file__).resolve().parents[1]


def resolve_reference(source: Path, reference: str) -> Path:
    """Resolve a pentest skill reference from the skill package root."""
    source = source.resolve()
    for parent in (source.parent, *source.parents):
        if parent.name == "pentest" and parent.parent.name == "skills":
            return (parent / reference).resolve()
    raise ValueError(f"source is not inside skills/pentest: {source}")


def check_release() -> ReleaseCheckResult:
    """Run all release gate checks. This is a REAL gate — failures add errors
    and cause a non-zero exit code (see CLI cmd_check_release)."""
    result = ReleaseCheckResult()
    root = _plugin_root()

    # 1. plugin.yaml version
    plugin_yaml = root / "plugin.yaml"
    provides_tools: list[str] = []
    if plugin_yaml.exists():
        import yaml

        data = yaml.safe_load(plugin_yaml.read_text(encoding="utf-8"))
        version = data.get("version", "0.0.0")
        provides_tools = list(data.get("provides_tools", []) or [])
        if not re.match(r"^\d+\.\d+\.\d+", version):
            result.add_error(f"plugin.yaml version '{version}' is not a valid semver")
        else:
            result.add_info(f"plugin.yaml version: {version}")
    else:
        result.add_error("plugin.yaml not found")

    # 2. CHANGELOG.md
    changelog = root.parents[1] / "CHANGELOG.md"
    if changelog.exists():
        result.add_info("CHANGELOG.md present")
    else:
        result.add_warning("CHANGELOG.md not found")

    # 3. Isolated plugin import (catches broken module-level code / imports).
    module_name = "violin_guard_release_check"
    old_module = sys.modules.get(module_name)
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
        mod = None
    finally:
        sys.path.pop(0)
        if old_module is None:
            sys.modules.pop(module_name, None)
        else:
            sys.modules[module_name] = old_module

    # 3b. Manifest vs registered tools.
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

    # 4. Heavy checks (ruff + pytest), opt-out via env.
    if os.environ.get("VIOLIN_CHECK_RELEASE_SKIP_HEAVY") != "1":
        repo_root = str(root.parents[1])
        try:
            ruff = subprocess.run(
                [sys.executable, "-m", "ruff", "check", "."],
                cwd=repo_root,
                capture_output=True,
                text=True,
            )
            if ruff.returncode != 0:
                result.add_error(
                    "ruff check failed:\n" + (ruff.stdout or ruff.stderr).strip()[:2000]
                )
            else:
                result.add_info("ruff check passed")
        except FileNotFoundError:
            result.add_warning("ruff not installed; skipped")
        try:
            pytest = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "pytest",
                    "-q",
                    "-p",
                    "no:cacheprovider",
                    "--basetemp",
                    str(Path(repo_root) / "engagements" / ".pytest-release"),
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
    else:
        result.add_info("heavy checks skipped (VIOLIN_CHECK_RELEASE_SKIP_HEAVY=1)")

    # 5. Tests directory
    tests_dir = root.parents[1] / "tests"
    if tests_dir.exists():
        result.add_info(f"tests directory found: {tests_dir}")
    else:
        result.add_warning("tests directory not found")

    # 6. Skill documentation staleness scan (corrected forbidden set).
    profile_root = root.parents[1]
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
    if skills_root.exists():
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

    return result


def validate_plugin_structure() -> StructureResult:
    """Validate plugin directory structure against Hermes conventions."""
    result = StructureResult()
    root = _plugin_root()

    # Required files
    required = {
        "plugin.yaml": "plugin manifest",
        "__init__.py": "registration entry point",
        "schemas.py": "tool schemas",
        "tools.py": "tool handlers",
    }

    for fname, desc in required.items():
        path = root / fname
        if path.exists():
            result.add_info(f"found {fname} ({desc})")
        else:
            result.add_error(f"missing {fname} ({desc})")

    # core/ subpackage
    core_dir = root / "core"
    if core_dir.is_dir():
        core_modules = [
            "service.py",
            "command.py",
            "ptt.py",
            "hypotheses.py",
            "phases.py",
            "state.py",
            "execution.py",
            "adapters.py",
            "bootstrap.py",
            "release.py",
        ]
        for mod in core_modules:
            if (core_dir / mod).exists():
                result.add_info(f"core/{mod} present")
            else:
                result.add_warning(f"core/{mod} missing")

        # __init__.py exports
        init_content = (core_dir / "__init__.py").read_text(encoding="utf-8")
        if "__all__" in init_content:
            result.add_info("core/__init__.py defines __all__")
        else:
            result.add_warning("core/__init__.py missing __all__")
    else:
        result.add_error("core/ subpackage directory missing")

    # plugin.yaml structure
    plugin_yaml = root / "plugin.yaml"
    if plugin_yaml.exists():
        import yaml

        try:
            data = yaml.safe_load(plugin_yaml.read_text(encoding="utf-8"))
            for key in ("name", "version", "description", "provides_tools"):
                if key in data:
                    result.add_info(f"plugin.yaml has {key}")
                else:
                    result.add_error(f"plugin.yaml missing {key}")
        except Exception as e:
            result.add_error(f"plugin.yaml parse error: {e}")

    # __init__.py has register(ctx)
    init_py = root / "__init__.py"
    if init_py.exists():
        content = init_py.read_text(encoding="utf-8")
        if "def register(" in content:
            result.add_info("__init__.py has register(ctx)")
        else:
            result.add_error("__init__.py missing register(ctx)")

    return result
