"""Release-readiness checks for the Violin guard package."""

from __future__ import annotations

import argparse
import importlib
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCRIPTS = ROOT / "scripts"
for import_path in (ROOT, SCRIPTS):
    if str(import_path) not in sys.path:
        sys.path.insert(0, str(import_path))

from guard.core import CheckResult, as_list, load_yaml  # noqa: E402


def local_markdown_links(path: Path, text: str) -> list[str]:
    refs: set[str] = set()
    # Inline backtick references: `path/to/file.md` or `file.md`
    # Skip anything that looks like a shell command (starts with `cp `, `mkdir `, `cat `, `echo `, `ls `, etc.)
    shell_command_prefixes = (
        "cp ",
        "mkdir ",
        "cat ",
        "echo ",
        "ls ",
        "cd ",
        "mv ",
        "rm ",
        "touch ",
        "chmod ",
        "python",
        "bash ",
        "sh ",
        "tar ",
        "grep ",
        "sed ",
        "awk ",
        "command ",
        "export ",
        "read_file",
        "write_file",
        "search_files",
        "terminal(",
        "clarify(",
        "session_search",
        "skill_view",
        "delegate_task",
    )
    for match in re.findall(r"`([^`]+\.md)`", text):
        candidate = match.strip()
        # Skip shell command examples
        if any(candidate.startswith(prefix) for prefix in shell_command_prefixes):
            continue
        # Skip runtime paths under $ENG_DIR/ — they only exist per-engagement, not in the repo
        if (
            "$ENG_DIR" in candidate
            or "engagements/" in candidate
            or candidate.startswith("state/")
            or candidate.startswith("evidence/")
        ):
            continue
        # Skip paths that are part of a longer shell command (e.g., "foo.md $ENG_DIR/")
        if " " in candidate and not candidate.startswith(
            ("./", "/", "skills/", "references/", "playbooks/", "templates/")
        ):
            continue
        # Skip bare filenames that look like runtime artifacts
        if candidate in {
            "hypotheses.md",
            "hypothesis-board.md",
            "ptt.md",
            "history.md",
            "phase-summary.md",
            "scope.yaml",
        }:
            continue
        refs.add(candidate)
    # Markdown link references: [text](path/to/file.md) — only relative, no scheme
    for match in re.findall(r"\]\(([^)]+\.md)\)", text):
        if "://" in match:
            continue
        refs.add(match)
    return sorted(refs)


def resolve_reference(base: Path, ref: str) -> Path:
    cleaned = ref.strip().split("#", 1)[0]
    if "$" in cleaned or "<" in cleaned:
        return Path()
    if cleaned.startswith("/"):
        return ROOT / cleaned.lstrip("/")
    if cleaned.startswith("skills/") or cleaned in {
        "README.md",
        "SOUL.md",
        "PLAN.md",
        ".hermes.md",
    }:
        return ROOT / cleaned
    if cleaned.startswith(("playbooks/", "references/")):
        # Playbooks commonly refer to sibling skill folders as
        # `references/foo.md` / `playbooks/foo.md`; resolve those from the
        # pentest skill root, not from the playbook's own directory.
        return ROOT / "skills/pentest" / cleaned
    if cleaned.startswith("templates/"):
        return ROOT / "skills/pentest" / cleaned
    return base.parent / cleaned


def check_release(_: argparse.Namespace) -> int:
    result = CheckResult()
    for yaml_path in (
        "distribution.yaml",
        "config.yaml",
        "skills/pentest/templates/scope-template.yaml",
    ):
        try:
            load_yaml(ROOT / yaml_path)
            result.add_info(f"YAML valid: {yaml_path}")
        except Exception as exc:  # noqa: BLE001 - report any validation failure
            result.add_error(f"YAML invalid: {yaml_path}: {exc}")

    distribution = load_yaml(ROOT / "distribution.yaml")
    for item in as_list(distribution.get("distribution_owned")):
        if not (ROOT / str(item)).exists():
            result.add_error(f"distribution_owned path missing: {item}")

    declared_tools = as_list(
        load_yaml(ROOT / "plugins/violin_guard/plugin.yaml").get("provides_tools")
    )
    if len(declared_tools) != 18:
        result.add_error(f"expected 18 plugin tools, found {len(declared_tools)}")
    else:
        result.add_info("18 plugin tools declared")

    playbooks = sorted((ROOT / "skills/pentest/playbooks").glob("*.md"))
    if len(playbooks) != 31:
        result.add_error(f"expected 31 playbooks, found {len(playbooks)}")
    else:
        result.add_info("31 playbooks present")

    templates = sorted((ROOT / "skills/pentest/templates").glob("*"))
    if len(templates) != 10:
        result.add_error(f"expected 10 templates, found {len(templates)}")
    else:
        result.add_info("10 templates present")

    try:
        module = importlib.import_module("plugins.violin_guard")
        if not module._TOOLS:
            raise ImportError("plugin registered no tools")
        result.add_info(f"plugin import passed ({len(module._TOOLS)} tools)")
    except Exception as exc:  # noqa: BLE001 - release check should report the cause
        result.add_error(f"plugin import failed: {exc}")

    isolated_import = subprocess.run(
        [
            sys.executable,
            "-I",
            "-c",
            (
                "import sys; "
                f"sys.path.insert(0, {str(ROOT)!r}); "
                "import plugins.violin_guard; "
                "print('plugin-isolated-import-ok')"
            ),
        ],
        cwd=ROOT.parent,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=30,
        check=False,
    )
    if isolated_import.returncode:
        result.add_error(
            "plugin isolated import failed: "
            + (isolated_import.stdout + isolated_import.stderr).strip()
        )
    else:
        result.add_info("plugin isolated import passed")

    phase_playbooks = {
        "scoping",
        "recon",
        "vuln-research",
        "exploitation",
        "reporting",
        "tools",
        "post-exploitation",
    }
    for playbook in playbooks:
        text = playbook.read_text(encoding="utf-8")
        if playbook.stem not in phase_playbooks:
            for section in ("## Evidence", "## Stop", "## Blocked"):
                if section not in text:
                    result.add_error(f"{playbook.relative_to(ROOT)} missing {section}")
        if re.search(r"\./evidence\b|\./report\b", text):
            result.add_error(
                f"{playbook.relative_to(ROOT)} contains stale ./evidence or ./report path"
            )

    for md_path in [
        ROOT / "README.md",
        ROOT / "SOUL.md",
        ROOT / ".hermes.md",
        ROOT / "skills/pentest/SKILL.md",
        *playbooks,
    ]:
        text = md_path.read_text(encoding="utf-8")
        for ref in local_markdown_links(md_path, text):
            resolved = resolve_reference(md_path, ref)
            if str(resolved) == ".":
                continue
            if not resolved.exists():
                result.add_error(
                    f"{md_path.relative_to(ROOT)} references missing markdown file: {ref}"
                )

    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    if "fully autonomous" in readme.lower():
        result.add_error("README still claims fully autonomous operation")
    if "supervised agentic" not in readme.lower():
        result.add_warning("README does not use supervised agentic positioning")

    if not (ROOT / "scripts/smoke-test.ps1").exists():
        result.add_error("Windows smoke test missing: scripts/smoke-test.ps1")

    if not result.errors:
        test = subprocess.run(
            [sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider"],
            cwd=ROOT,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=180,
            check=False,
        )
        if test.returncode:
            result.add_error(
                "pytest failed during release validation: "
                + (test.stdout + test.stderr).strip()[-2000:]
            )
        else:
            result.add_info("pytest passed")

    if not result.errors and not result.warnings:
        result.add_info("release check passed")
    result.print()
    return result.exit_code()
