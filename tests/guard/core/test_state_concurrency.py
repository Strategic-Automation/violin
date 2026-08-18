"""State transitions must not lose updates under concurrent executor calls."""

from __future__ import annotations

import concurrent.futures
import json

from plugins.violin_guard import state


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
