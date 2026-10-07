"""Guard dependencies must be visible to Hermes without the root project."""

import ast
import tomllib
from pathlib import Path

import yaml
from packaging.requirements import Requirement


def test_plugin_declares_imported_runtime_dependencies():
    root = Path(__file__).resolve().parents[3]
    plugin = root / "plugins" / "violin_guard"
    manifest = yaml.safe_load((plugin / "plugin.yaml").read_text(encoding="utf-8"))
    declared = {Requirement(spec).name: spec for spec in manifest["pip_dependencies"]}
    project = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))
    development = {Requirement(spec).name: spec for spec in project["project"]["dependencies"]}
    distributions = {"yaml": "pyyaml", "markdown_it": "markdown-it-py"}
    imports = set()
    for source in plugin.rglob("*.py"):
        for node in ast.walk(ast.parse(source.read_text(encoding="utf-8"))):
            if isinstance(node, ast.Import):
                imports.update(alias.name.split(".")[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                imports.add(node.module.split(".")[0])
    required = {distributions.get(name, name) for name in imports} & development.keys()
    assert required <= declared.keys()
    assert all(spec == development[name] for name, spec in declared.items())
