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


@pytest.mark.parametrize(
    ("command", "expected"),
    [
        # A base-URL variable assigned as a plain statement (no ``export``) must
        # still resolve: avoiding a hardcoded host is normal practice, and an
        # unexpanded ``$B/...`` makes every endpoint correlation fail.
        ('B=https://host; curl -sS -i "$B/orders/1"', [("GET", "/orders/1")]),
        ('B=https://host\ncurl -sS -i "$B/users/"', [("GET", "/users/")]),
        ('B="https://host"; curl -sS "$B/coupons"', [("GET", "/coupons")]),
        (
            'B=https://host; export C=https://host; curl -sS "$B/a"; curl -sS "${C}/b"',
            [("GET", "/a"), ("GET", "/b")],
        ),
        ('B=https://host curl -sS "$B/env-prefixed"', [("GET", "/env-prefixed")]),
    ],
)
def test_base_url_variable_assignment_resolves_requests(command, expected):
    assert [(item.method, item.url.path) for item in _command_requests(command)] == expected


def test_command_substitution_is_not_treated_as_a_variable():
    """``$(...)`` must stay untouched: only true variable refs are expanded."""
    command = 'B=https://host; curl -sS "$B/users/$(cat id.txt)"'
    requests = _command_requests(command)

    assert len(requests) == 1
    assert requests[0].url.path.startswith("/users/")
    assert "$(" in requests[0].url.path


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


def test_receipt_authenticated_json_response_is_read_as_saved_evidence(tmp_path: Path):
    """A signed JSON HTTP body must reach the same proof reader as a text body."""
    key = b"s" * 32
    body = tmp_path / "evidence" / "vuln-research" / "response.json"
    body.parent.mkdir(parents=True)
    body.write_text('{"ok":true}', encoding="utf-8")
    relative = body.relative_to(tmp_path).as_posix()
    receipt = _write_receipt(
        tmp_path,
        key=key,
        command=f"curl -sS -o {relative} -w 'HTTP %{{http_code}}\\n' https://host/status",
        proof="HTTP 200\n",
        declared_evidence_outputs=[relative],
    )
    bundles = receipt_bundles(tmp_path, [receipt], evidence_paths=[relative], receipt_key=key)
    assert any(
        bundle.receipt_path == body.resolve() and '{"ok":true}' in bundle.proof
        for bundle in bundles
    )
    body.write_text('{"ok":false}', encoding="utf-8")
    assert receipt_bundles(tmp_path, [receipt], evidence_paths=[relative], receipt_key=key) == []


def test_script_batch_requires_correlated_observations(tmp_path: Path):
    key = b"s" * 32
    receipt = _write_receipt(
        tmp_path,
        key=key,
        command="python3 -c \"import requests; requests.get('https://host/a'); requests.get('https://host/b')\"",
        proof="HTTP/1.1 403 Forbidden\nHTTP/1.1 200 OK\n",
    )
    assert receipt_bundles(tmp_path, [receipt], receipt_key=key) == []


def test_arithmetic_expansion_does_not_abort_request_correlation():
    """A receipt using ``$((...))`` must still correlate its requests.

    bashlex raises NotImplementedError for arithmetic expansion rather than a parse
    error. If that escapes the parser fallback, scoring dies for the whole run and
    every finding loses its request attribution, not just this one command.
    """
    command = 'for i in 1 2 3; do n=$((i+1)); curl -sS -i "https://host/items/$n"; done'
    requests = _command_requests(command)

    assert [item.method for item in requests] == ["GET"]
    assert requests[0].url.path.startswith("/items/")
