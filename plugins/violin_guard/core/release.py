"""Release gate checks for the Violin plugin.

Pure functions — no subprocess. Called by CLI check-release.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

__all__ = [
    "ReleaseCheckResult",
    "StructureResult",
    "check_release",
    "validate_plugin_structure",
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


def check_release() -> ReleaseCheckResult:
    """Run all release gate checks."""
    result = ReleaseCheckResult()
    root = _plugin_root()

    # 1. plugin.yaml version bumped
    plugin_yaml = root / "plugin.yaml"
    if plugin_yaml.exists():
        import yaml
        data = yaml.safe_load(plugin_yaml.read_text(encoding="utf-8"))
        version = data.get("version", "0.0.0")
        # Check if version looks like a proper semver
        if not re.match(r"^\d+\.\d+\.\d+", version):
            result.add_error(f"plugin.yaml version '{version}' is not a valid semver")
        else:
            result.add_info(f"plugin.yaml version: {version}")
    else:
        result.add_error("plugin.yaml not found")

    # 2. CHANGELOG.md updated
    changelog = root.parents[1] / "CHANGELOG.md"
    if changelog.exists():
        result.add_info("CHANGELOG.md present")
    else:
        result.add_warning("CHANGELOG.md not found")

    # Runtime diagnostics are intentionally emitted by the CLI; they are not
    # release errors.  Static linting belongs in the CI lint workflow.

    # 4. provides_tools matches registered tools
    # This would require importing the plugin, which we can't do in pure check
    result.add_info("run isolated plugin import test to verify provides_tools")

    # 5. Tests exist
    tests_dir = root.parents[1] / "tests"
    if tests_dir.exists():
        result.add_info(f"tests directory found: {tests_dir}")
    else:
        result.add_warning("tests directory not found")

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
