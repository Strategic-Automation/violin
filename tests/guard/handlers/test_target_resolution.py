"""Target resolution regression tests."""

import pytest

from plugins.violin_guard.core.commands.targets import resolve_target
from tests.guard.handlers._burst_helpers import (
    _run,
)
from tests.guard.handlers._burst_helpers import (
    eng as eng,
)


def test_target_role_preserves_ipv6_url_hostname():
    scope = {"targets": {"roles": {"web": "http://[2001:db8::1]:8080"}}}

    assert resolve_target(scope, role="web", host_query=None, field="host") == "2001:db8::1"


def test_target_role_preserves_malformed_url_for_review():
    scope = {"targets": {"roles": {"web": "http://[broken"}}}

    assert resolve_target(scope, role="web", host_query=None, field="host") == "http://[broken"


def test_target_resolution_rejects_conflicting_and_ambiguous_selectors():
    scope = {
        "targets": {
            "ip_addresses": ["10.10.10.10", "10.10.10.11"],
            "roles": {"web": ["10.10.10.10", "10.10.10.11"]},
        }
    }
    with pytest.raises(ValueError, match="exactly one of role or host"):
        resolve_target(scope, role="web", host_query="10.10.10.10", field="host")
    with pytest.raises(ValueError, match="ambiguous"):
        resolve_target(scope, role="web", host_query=None, field="host")
    with pytest.raises(ValueError, match="multiple targets"):
        resolve_target(scope, role=None, host_query=None, field="host")
    with pytest.raises(ValueError, match="not defined in scope.yaml"):
        resolve_target(scope, role="database", host_query=None, field="host")


def test_target_role_url(eng):
    """handle_target returns the first in-scope IP (canonical IP form)."""
    r = _run("target", "--eng-dir", str(eng), "--role", "web", "--field", "url")
    assert r.returncode == 0, r.stderr
    assert r.stdout.strip() == "10.10.10.10"


def test_target_role_url_returns_first_in_scope_ip(eng):
    """handle_target resolves a role to its in-scope target by returning the
    first in-scope IP; it does not perform scope validation (the per-command
    check-command gate is what enforces scope)."""
    scope = (eng / "scope" / "scope.yaml").read_text(encoding="utf-8")
    scope = scope.replace("in_scope_urls: []", "in_scope_urls: [http://10.10.10.10]")
    (eng / "scope" / "scope.yaml").write_text(scope, encoding="utf-8")
    r = _run("target", "--eng-dir", str(eng), "--role", "web", "--field", "url")
    assert r.returncode == 0, r.stderr
    assert r.stdout.strip() == "10.10.10.10"


def test_target_host_ip(eng):
    r = _run("target", "--eng-dir", str(eng), "--host", "10.10.10.10", "--field", "ip")
    assert r.returncode == 0, r.stderr
    assert r.stdout.strip() == "10.10.10.10"


def test_target_rejects_unauthorized_ip(eng):
    r = _run("target", "--eng-dir", str(eng), "--host", "10.99.99.99")
    assert r.returncode == 1
    assert "not present in scope.yaml" in r.stdout
    assert "targets.hostnames" not in r.stdout


def test_target_rejects_unknown_hostname_with_actionable_diagnostic(eng):
    r = _run("target", "--eng-dir", str(eng), "--host", "outside.example")

    assert r.returncode == 1
    canonical_scope = (eng / "scope" / "scope.yaml").resolve()
    assert "outside.example" in r.stdout
    assert str(canonical_scope) in r.stdout
    assert "targets.hostnames" in r.stdout
    assert "targets.in_scope_urls" in r.stdout
    assert (
        f'uv run python scripts/violin_guard.py validate-scope --scope "{canonical_scope}"'
        in r.stdout
    )
    assert "confirm authorization before editing scope.yaml" in r.stdout.lower()
    assert "never edits scope.yaml automatically" in r.stdout


def test_target_requires_eng_dir():
    r = _run("target", "--host", "10.10.10.10")
    assert r.returncode == 2  # argparse: required argument missing
