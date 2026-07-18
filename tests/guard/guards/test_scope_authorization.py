"""Fail-closed authorization and target-scope regression tests."""

from __future__ import annotations

from pathlib import Path

from plugins.violin_guard.command import validate_scope
from plugins.violin_guard.targets import (
    check_scope_targets,
    extract_target_candidates,
    normalise_target,
)


def _write_scope(path: Path, *, confirmed: bool = True, callback_hosts: str = "10.10.14.5") -> None:
    path.write_text(
        f"""targets:
  ip_addresses: [10.10.10.10]
  cidrs: [2001:db8::/32]
  domains: [allowed.example]
assessment_hosts:
  callback_hosts: [{callback_hosts}]
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


def test_unc_paths_expose_their_authority_as_a_target() -> None:
    assert extract_target_candidates("smbclient //10.10.10.10/Share") == ["10.10.10.10"]
    assert "allowed.example" in extract_target_candidates(
        "mount //allowed.example/share /mnt/share"
    )


def test_dotted_arguments_are_not_treated_as_network_targets_when_they_are_paths() -> None:
    assert extract_target_candidates("python3 exploit.py 10.10.10.10") == ["10.10.10.10"]
    assert extract_target_candidates(
        "smbclient //10.10.10.10/share -c 'put /tmp/x payload.vsix'"
    ) == ["10.10.10.10"]


def test_explicit_target_keeps_unknown_bare_hostnames_reviewable(
    tmp_path: Path,
) -> None:
    scope = tmp_path / "scope.yaml"
    _write_scope(scope)

    harmless = check_scope_targets(
        scope, "python3 -c 'sock.close()' cctv.htb_notes", primary_target="10.10.10.10"
    )
    assert not harmless.errors
    assert not harmless.warnings

    bare = check_scope_targets(scope, "curl outside.example", primary_target="10.10.10.10")
    assert any("outside.example" in warning for warning in bare.warnings)

    host_path = check_scope_targets(
        scope, "curl outside.example/status", primary_target="10.10.10.10"
    )
    assert any("outside.example" in warning for warning in host_path.warnings)

    url = check_scope_targets(
        scope, "curl https://outside.example/status", primary_target="10.10.10.10"
    )
    assert any("outside.example" in warning for warning in url.warnings)

    blocked = check_scope_targets(scope, "nmap 10.10.10.99", primary_target="10.10.10.10")
    assert blocked.errors


def test_legacy_descriptive_target_normalises_to_host() -> None:
    assert normalise_target("cctv.htb (/zm/index.php, camera portal)") == "cctv.htb"


def test_callback_hosts_are_secondary_only_and_exclusions_still_win(tmp_path: Path) -> None:
    scope = tmp_path / "scope.yaml"
    _write_scope(scope, callback_hosts="10.10.14.5, 10.10.10.99")

    callback = check_scope_targets(
        scope,
        "bash -c 'echo ready > /dev/tcp/10.10.14.5/4444'",
        primary_target="10.10.10.10",
    )
    assert not callback.errors
    assert not callback.warnings

    unconfigured = check_scope_targets(
        scope, "bash -c 'echo ready > /dev/tcp/10.10.14.6/4444'", primary_target="10.10.10.10"
    )
    assert any("10.10.14.6" in error for error in unconfigured.errors)

    callback_as_primary = check_scope_targets(
        scope, "nc -l -v -s 10.10.14.5 4444", primary_target="10.10.14.5"
    )
    assert any("10.10.14.5" in error for error in callback_as_primary.errors)

    excluded = check_scope_targets(
        scope, "nc -l -v -s 10.10.10.99 4444", primary_target="10.10.10.10"
    )
    assert any("excluded target 10.10.10.99" in error for error in excluded.errors)
