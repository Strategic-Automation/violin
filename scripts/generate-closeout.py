#!/usr/bin/env python3
"""Convenience CLI entrypoint for generating closeout artifacts."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

_PROFILE_ROOT = Path(__file__).resolve().parent.parent
if str(_PROFILE_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROFILE_ROOT))


from plugins.violin_guard.core import findings  # noqa: E402


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
