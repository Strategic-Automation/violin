#!/usr/bin/env python3
"""Convenience CLI entrypoint for generating closeout artifacts with dynamic venv discovery."""

from __future__ import annotations

import argparse
import sys

if __package__:
    from .cli_environment import cli_imports
else:
    from cli_environment import cli_imports

with cli_imports():
    from plugins.violin_guard.core import findings


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Render findings.yaml and report.md from evidence/findings.jsonl"
    )
    parser.add_argument("--eng-dir", required=True, help="Engagement directory path")
    parser.add_argument("--target", required=True, help="Assessment target")
    parser.add_argument("--force", action="store_true", help="Overwrite existing artifacts")

    args = parser.parse_args(argv)
    result = findings.generate_closeout(args.eng_dir, target=args.target, force=args.force)
    result.print()
    return result.exit_code()


if __name__ == "__main__":
    # If invoked with 'generate-closeout' as first positional arg, strip it
    cli_args = sys.argv[1:]
    if cli_args and cli_args[0] == "generate-closeout":
        cli_args = cli_args[1:]
    sys.exit(main(cli_args))
