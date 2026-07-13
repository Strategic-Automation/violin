"""Fail-closed authorization and target-scope regression tests."""

from __future__ import annotations

from pathlib import Path

from plugins.violin_guard.core.command import check_scope_targets, validate_scope


def _write_scope(path: Path, *, confirmed: bool = True) -> None:
    path.write_text(
        f"""targets:
  ip_addresses: [10.10.10.10]
  cidrs: [2001:db8::/32]
  domains: [allowed.example]
exclusions:
  ip_addresses: [10.10.10.99]
  cidrs: [2001:db8:dead::/48]
  domains: [excluded.example]
authorized_parties: [test owner]
authorisation:
  confirmed: {str(confirmed).lower()}
rules_of_engagement:
  allowed_actions: [host/port discovery, exploit validation]
  forbidden_actions: [post-exploitation]
engagement:
  date: "2026-07-13"
""",
        encoding="utf-8",
    )


def test_unconfirmed_scope_is_a_hard_block(tmp_path: Path) -> None:
    scope = tmp_path / "scope.yaml"
    _write_scope(scope, confirmed=False)
    assert any("authorisation.confirmed" in error for error in validate_scope(scope).errors)


def test_exclusions_and_ipv6_cidrs_are_enforced(tmp_path: Path) -> None:
    scope = tmp_path / "scope.yaml"
    _write_scope(scope)

    assert check_scope_targets(scope, "nmap 10.10.10.99").errors
    assert check_scope_targets(scope, "nmap 2001:db8:dead::1").errors
    assert not check_scope_targets(scope, "nmap 2001:db8:beef::1").errors
    assert check_scope_targets(scope, "curl https://excluded.example").errors
