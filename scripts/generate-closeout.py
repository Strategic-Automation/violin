#!/usr/bin/env python3
"""Convenience CLI entrypoint for generating closeout artifacts with dynamic venv discovery."""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
from pathlib import Path

_PROFILE_ROOT = Path(__file__).resolve().parent.parent
if str(_PROFILE_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROFILE_ROOT))

from scripts.cli_environment import project_imports


def _ensure_venv() -> None:
    try:
        import pydantic  # noqa: F401

        return
    except ImportError:
        pass

    candidates: list[Path] = []
    if os.getenv("VIRTUAL_ENV"):
        candidates.append(Path(os.environ["VIRTUAL_ENV"]))
    candidates.extend(
        [
            _PROFILE_ROOT / ".venv",
            _PROFILE_ROOT.parent / ".venv",
            Path("/violin/.venv"),
        ]
    )

    for venv in candidates:
        if not venv.is_dir():
            continue
        site_packages = list(venv.glob("lib/python*/site-packages")) + list(
            venv.glob("Lib/site-packages")
        )
        for sp in site_packages:
            if sp.is_dir() and str(sp) not in sys.path:
                sys.path.insert(0, str(sp))
        try:
            import pydantic  # noqa: F401

            return
        except ImportError:
            pass

        for exe_name in ("bin/python", "bin/python3", "Scripts/python.exe", "Scripts/python"):
            exe = venv / exe_name
            if exe.is_file() and Path(sys.executable).resolve() != exe.resolve():
                res = subprocess.run([str(exe), *sys.argv], check=False)
                sys.exit(res.returncode)


with project_imports(_PROFILE_ROOT):
    _ensure_venv()

    from plugins.violin_guard.core import findings


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Render findings.yaml and report.md from evidence/findings.jsonl"
    )
    parser.add_argument("--eng-dir", required=True, help="Engagement directory path")
    parser.add_argument("--target", required=True, help="Assessment target")
    parser.add_argument("--force", action="store_true", help="Overwrite existing artifacts")

    args = parser.parse_args(argv)
    try:
        yaml_path = findings.generate_findings_yaml(args.eng_dir, force=args.force)
        report_path = findings.generate_report_md(
            args.eng_dir, target=args.target, force=args.force
        )
    except ValueError as exc:
        print(f"BLOCK: {exc}")
        return 1
    print(f"OK: wrote {yaml_path}")
    print(f"OK: wrote {report_path}")
    return 0


if __name__ == "__main__":
    # If invoked with 'generate-closeout' as first positional arg, strip it
    cli_args = sys.argv[1:]
    if cli_args and cli_args[0] == "generate-closeout":
        cli_args = cli_args[1:]
    sys.exit(main(cli_args))
