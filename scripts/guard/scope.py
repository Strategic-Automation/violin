"""Scope validation for the Violin guard package."""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any

from guard.core import as_list, load_yaml, CheckResult, validate_scope_data


def validate_scope(args: argparse.Namespace) -> int:
    scope_path = Path(args.scope)
    if not scope_path.exists():
        result = CheckResult()
        result.add_error(f"scope file not found: {scope_path}")
        result.add_info("BOOTSTRAP REQUIRED: run the engagement bootstrap from playbooks/scoping.md §0 before any target interaction")
        result.print()
        return 1
    result = validate_scope_data(load_yaml(scope_path))
    result.print()
    return result.exit_code()
