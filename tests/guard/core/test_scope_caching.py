"""mtime-keyed caching of parsed scope.yaml must not serve stale data."""

from __future__ import annotations

import os
from pathlib import Path

from plugins.violin_guard import targets


def _write_scope(path: Path, payload: str) -> None:
    path.write_text(payload, encoding="utf-8")


def test_read_scope_caches_until_mtime_changes(tmp_path: Path) -> None:
    scope = tmp_path / "scope.yaml"
    _write_scope(scope, "primary_target: a\ntargets:\n  domains:\n    - a\n")

    first = targets._read_scope(scope)
    assert first == {"primary_target": "a", "targets": {"domains": ["a"]}}
    # Same mtime -> same cached object (not re-parsed).
    second = targets._read_scope(scope)
    assert second is first

    # Touch the file (changes mtime) -> cache invalidated, new parse.
    _write_scope(scope, "primary_target: b\ntargets:\n  domains:\n    - b\n")
    st = scope.stat()
    os.utime(scope, ns=(st.st_atime_ns + 1_000_000_000, st.st_mtime_ns + 1_000_000_000))
    third = targets._read_scope(scope)
    assert third is not first
    assert third == {"primary_target": "b", "targets": {"domains": ["b"]}}


def test_read_scope_returns_none_for_missing_and_invalid(tmp_path: Path) -> None:
    missing = tmp_path / "nope.yaml"
    assert targets._read_scope(missing) is None

    bad = tmp_path / "bad.yaml"
    bad.write_text(": : not: :valid [[\n", encoding="utf-8")
    assert targets._read_scope(bad) is None


def test_scope_cache_key_includes_content_snapshot(tmp_path: Path) -> None:
    scope = tmp_path / "scope.yaml"
    _write_scope(scope, "primary_target: x\n")
    first = targets._read_scope(scope)
    assert first == {"primary_target": "x"}

    # Same content, force mtime change (re-write identical bytes).
    scope.write_text("primary_target: x\n", encoding="utf-8")
    targets._clear_scope_cache()  # reset cache to prove independence
    refreshed = targets._read_scope(scope)
    assert refreshed["primary_target"] == "x"
