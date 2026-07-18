"""State transitions must not lose updates under concurrent executor calls."""

from __future__ import annotations

import concurrent.futures
import json

from plugins.violin_guard import state


def test_concurrent_credit_spends_are_serialised(tmp_path):
    eng = tmp_path / "engagement"
    sync = eng / "state" / "sync.json"
    sync.parent.mkdir(parents=True)
    sync.write_text(json.dumps({"credit": 50}), encoding="utf-8")

    with concurrent.futures.ThreadPoolExecutor(max_workers=16) as pool:
        results = list(pool.map(lambda _: state.spend_sync_credit(eng, "RECON"), range(25)))

    assert state.sync_credit_remaining(eng) == 25
    assert sorted(results) == list(range(25, 50))
