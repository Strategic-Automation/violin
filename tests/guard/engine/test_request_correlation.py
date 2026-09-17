"""Request attribution and receipt eligibility must fail closed."""

from pathlib import Path

import pytest

from benchmark.proof import _command_requests, _sub_commands, receipt_bundles
from plugins.violin_guard.core import findings, receipt_integrity
from tests.guard.engine.test_benchmark_runner import _write_receipt


@pytest.mark.parametrize(
    ("command", "expected"),
    [
        (
            "curl -X DELETE https://host/orders/1 -d '{}'; curl https://host/coupons",
            [("DELETE", "/orders/1"), ("GET", "/coupons")],
        ),
        (
            "curl -d u=a https://host/login; curl https://host/users/",
            [("POST", "/login"), ("GET", "/users/")],
        ),
        (
            "sh -c 'curl --request=PUT https://host/a; curl -I https://host/b'",
            [("PUT", "/a"), ("HEAD", "/b")],
        ),
        ("curl --data-urlencode x=y -G https://host/a", [("GET", "/a")]),
        ("curl https://host/a; curl https://host/a", [("GET", "/a"), ("GET", "/a")]),
    ],
)
def test_methods_are_local_to_each_request(command, expected):
    assert [(item.method, item.url.path) for item in _command_requests(command)] == expected


def test_shell_split_preserves_quoted_semicolons():
    parts = _sub_commands("curl -d 'value=a;b' https://host/a; curl https://host/b")
    assert len(parts) == 2
    assert "value=a;b" in parts[0]


@pytest.mark.parametrize("status", ["completed_with_error", "running", "starting"])
def test_receipt_status_is_consistent_for_findings_and_scoring(tmp_path, monkeypatch, status):
    key = b"s" * 32
    monkeypatch.setattr(receipt_integrity, "_RUNTIME_KEY", key)
    monkeypatch.setattr(receipt_integrity, "_RUNTIME_SIGNING_KEY", None)
    receipt = _write_receipt(
        tmp_path,
        key=key,
        command="curl https://host/a",
        proof="HTTP/1.1 403 Forbidden\n",
        status=status,
    )
    bundles = receipt_bundles(tmp_path, [receipt], receipt_key=key)
    if status == "completed_with_error":
        assert bundles and bundles[0].executed
        assert findings._verified_receipt(tmp_path, receipt)
    else:
        assert bundles == []
        with pytest.raises(ValueError, match="reviewable result"):
            findings._verified_receipt(tmp_path, receipt)


def test_script_batch_requires_correlated_observations(tmp_path: Path):
    key = b"s" * 32
    receipt = _write_receipt(
        tmp_path,
        key=key,
        command="python3 -c \"import requests; requests.get('https://host/a'); requests.get('https://host/b')\"",
        proof="HTTP/1.1 403 Forbidden\nHTTP/1.1 200 OK\n",
    )
    assert receipt_bundles(tmp_path, [receipt], receipt_key=key) == []
