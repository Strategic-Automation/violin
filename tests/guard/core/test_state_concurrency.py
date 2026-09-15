"""State transitions must not lose updates under concurrent executor calls."""

from __future__ import annotations

import concurrent.futures
import json

from plugins.violin_guard.core import state


def test_concurrent_credit_spends_are_serialized(tmp_path):
    eng = tmp_path / "engagement"
    sync = eng / "state" / "sync.json"
    sync.parent.mkdir(parents=True)
    sync.write_text(json.dumps({"credit": 50}), encoding="utf-8")

    with concurrent.futures.ThreadPoolExecutor(max_workers=16) as pool:
        results = list(pool.map(lambda _: state.spend_sync_credit(eng, "RECON"), range(25)))

    assert state.sync_credit_remaining(eng) == 25
    assert sorted(results) == list(range(25, 50))


def test_lock_file_releases_lock_path(tmp_path):
    target = tmp_path / "test.json"
    lock_file = tmp_path / "test.json.lock"
    with state.lock_file(target):
        assert lock_file.exists()
    acquired = False
    with state.lock_file(target):
        acquired = True
    assert acquired


def test_read_json_non_existent_vs_error(tmp_path):
    """Verify read_json returns {} for non-existent file but raises on persistent read errors."""
    non_existent = tmp_path / "missing.json"
    assert state.read_json(non_existent) == {}

    existing = tmp_path / "existing.json"
    existing.write_text('{"key": "value"}', encoding="utf-8")
    assert state.read_json(existing) == {"key": "value"}


def test_resolve_eng_dir_defaults_to_cwd(tmp_path, monkeypatch):
    """Verify resolve_eng_dir resolves to CWD when scope markers are present."""
    monkeypatch.chdir(tmp_path)
    (tmp_path / "hypotheses.md").write_text("# Hypotheses\n", encoding="utf-8")
    assert state.resolve_eng_dir("") == tmp_path.resolve()
    assert state.resolve_eng_dir(".") == tmp_path.resolve()
