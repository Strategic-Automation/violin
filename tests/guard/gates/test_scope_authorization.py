"""Fail-closed authorization and target-scope regression tests."""

from __future__ import annotations

from pathlib import Path

from plugins.violin_guard.core.targets import (
    check_scope_targets,
    extract_target_candidates,
    normalize_target,
)
from plugins.violin_guard.gates.command import validate_scope


def _write_scope(path: Path, *, confirmed: bool = True, callback_hosts: str = "10.10.14.5") -> None:
    path.write_text(
        f"""targets:
  ip_addresses: [10.10.10.10]
  cidrs: [2001:db8::/32]
  domains: [allowed.example]
assessment_hosts:
  callback_hosts: [{callback_hosts}]
research_hosts: [github.com, 192.0.2.10]
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
    assert extract_target_candidates("cat evidence/recon/access.token") == []
    assert "urllib.request" not in extract_target_candidates(
        "python3 -c 'import urllib.request; urllib.request.urlopen(\"https://target.example\")'"
    )
    assert extract_target_candidates("python3 -m json.tool input.json") == []
    assert extract_target_candidates("curl -u user:pass jwt.io") == []


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


def test_legacy_descriptive_target_normalizes_to_host() -> None:
    assert normalize_target("cctv.htb (/zm/index.php, camera portal)") == "cctv.htb"


def test_callback_hosts_are_secondary_only_and_exclusions_still_win(tmp_path: Path) -> None:
    scope = tmp_path / "scope.yaml"
    _write_scope(scope, callback_hosts="10.10.14.5, listener.example, 10.10.10.99")

    callback = check_scope_targets(
        scope,
        "bash -c 'echo ready > /dev/tcp/10.10.14.5/4444'",
        primary_target="10.10.10.10",
    )
    assert not callback.errors
    assert not callback.warnings

    for host in ("listener.example", "github.com"):
        secondary = check_scope_targets(
            scope, f"curl https://{host}/status", primary_target="10.10.10.10"
        )
        assert not secondary.errors
        assert not secondary.warnings

    unconfigured = check_scope_targets(
        scope, "bash -c 'echo ready > /dev/tcp/10.10.14.6/4444'", primary_target="10.10.10.10"
    )
    assert any("10.10.14.6" in error for error in unconfigured.errors)

    callback_as_primary = check_scope_targets(
        scope, "nc -l -v -s 10.10.14.5 4444", primary_target="10.10.14.5"
    )
    assert any(
        "secondary-only endpoint 10.10.14.5" in error for error in callback_as_primary.errors
    )

    for host in ("listener.example", "github.com", "192.0.2.10"):
        primary = check_scope_targets(scope, f"curl https://{host}", primary_target=host)
        assert any(f"secondary-only endpoint {host}" in error for error in primary.errors)

    excluded = check_scope_targets(
        scope, "nc -l -v -s 10.10.10.99 4444", primary_target="10.10.10.10"
    )
    assert any("excluded target 10.10.10.99" in error for error in excluded.errors)


def test_direct_dev_tcp_redirection_is_checked_and_not_bookkeeping(tmp_path: Path) -> None:
    scope = tmp_path / "scope.yaml"
    _write_scope(scope, callback_hosts="10.10.10.10")

    result = check_scope_targets(
        scope,
        "echo ready > /dev/tcp/10.10.10.99/4444",
        primary_target="10.10.10.10",
    )
    assert any("10.10.10.99" in error for error in result.errors)


def test_parenthetical_scope_actions_are_permitted() -> None:
    from plugins.violin_guard.core.phases import Phase
    from plugins.violin_guard.gates.command import check_scope_authorization

    scope = {
        "rules_of_engagement": {
            "allowed_actions": ["exploit validation (in-scope, non-destructive)"],
            "forbidden_actions": [],
        }
    }
    res = check_scope_authorization(scope, Phase.EXPLOITATION)
    assert not res.errors


def test_vulnerability_research_permits_vuln_research_phase() -> None:
    from plugins.violin_guard.core.phases import Phase
    from plugins.violin_guard.gates.command import check_scope_authorization

    scope = {
        "rules_of_engagement": {
            "allowed_actions": ["vulnerability research"],
            "forbidden_actions": [],
        }
    }
    res = check_scope_authorization(scope, Phase.VULN_RESEARCH)
    assert not res.errors


_PAYLOAD_SCOPE = """\
targets:
  ip_addresses: [10.10.10.10]
  urls: [https://duck-store.escape.tech]
  domains: [allowed.example]
research_hosts: [github.com]
assessment_hosts:
  callback_hosts: [10.10.14.5]
exclusions:
  urls: [https://excluded.example]
  domains: [excluded.example]
authorized_parties: [test owner]
authorisation:
  confirmed: true
rules_of_engagement:
  allowed_actions: [vulnerability research, exploit validation]
engagement:
  date: "2026-07-13"
"""


def _write_payload_scope(path: Path) -> None:
    path.write_text(_PAYLOAD_SCOPE, encoding="utf-8")


def test_payload_url_hosts_inside_in_scope_url_are_allowed(tmp_path: Path) -> None:
    scope = tmp_path / "scope.yaml"
    _write_payload_scope(scope)

    # SSRF probe: the metadata IP is payload content, not a connection target
    allowed = check_scope_targets(
        scope,
        "curl 'https://duck-store.escape.tech/uploads/fetch-url?url=http://169.254.169.254/latest/meta-data/'",
        primary_target="https://duck-store.escape.tech",
    )
    assert not allowed.errors, allowed.errors
    assert not allowed.warnings, allowed.warnings


def test_payload_url_hosts_in_body_field_are_allowed(tmp_path: Path) -> None:
    scope = tmp_path / "scope.yaml"
    _write_payload_scope(scope)

    allowed = check_scope_targets(
        scope,
        "curl -X POST 'https://duck-store.escape.tech/api/v1/uploads/import-from-url' -d 'url=http://127.0.0.1:8080/private'",
        primary_target="https://duck-store.escape.tech",
    )
    assert not allowed.errors, allowed.errors


def test_direct_out_of_scope_connections_stay_blocked(tmp_path: Path) -> None:
    scope = tmp_path / "scope.yaml"
    _write_payload_scope(scope)

    for command in (
        "curl http://169.254.169.254/latest/meta-data/",
        "nmap 169.254.169.254",
        "bash -c 'echo x > /dev/tcp/169.254.169.254/80'",
        "curl http://10.10.10.99/",  # out-of-scope private IP as transport
    ):
        blocked = check_scope_targets(
            scope, command, primary_target="https://duck-store.escape.tech"
        )
        assert blocked.errors, f"expected block for: {command}"


def test_excluded_hosts_inside_payloads_stay_blocked(tmp_path: Path) -> None:
    scope = tmp_path / "scope.yaml"
    _write_payload_scope(scope)

    # exclusion must win even when the host is only payload content
    blocked = check_scope_targets(
        scope,
        "curl 'https://duck-store.escape.tech/uploads/fetch-url?url=https://excluded.example/secret'",
        primary_target="https://duck-store.escape.tech",
    )
    assert blocked.errors
    assert any("excluded" in error.lower() for error in blocked.errors)


def test_echo_label_ips_are_not_transport_targets(tmp_path: Path) -> None:
    scope = tmp_path / "scope.yaml"
    _write_payload_scope(scope)

    # A quoted text label mentioning an IP is not a connection target.
    # This is the exact guard friction seen in benchmarks: agents label
    # SSRF probes with echo strings and the bare IP inside the label was
    # parsed as an out-of-scope connection target.
    allowed = check_scope_targets(
        scope,
        "echo '=== SSRF 169.254.169.254 ==='; curl -s 'https://duck-store.escape.tech/uploads/fetch-url?url=http://169.254.169.254/latest/meta-data/'",
        primary_target="https://duck-store.escape.tech",
    )
    assert not allowed.errors, allowed.errors
    assert not allowed.warnings, allowed.warnings


def test_scope_authorization_error_message_provides_selection_list() -> None:
    from plugins.violin_guard.core.phases import Phase
    from plugins.violin_guard.gates.command import check_scope_authorization

    scope = {
        "rules_of_engagement": {
            "allowed_actions": ["vulnerability scanning"],
            "forbidden_actions": [],
        }
    }
    res = check_scope_authorization(scope, Phase.VULN_RESEARCH)
    assert len(res.errors) == 1
    err = res.errors[0]
    assert "scope/scope.yaml" in err
    assert "Select and add one of the following valid action strings for VULN_RESEARCH" in err
    assert "'vulnerability research'" in err
    assert "'cve-research'" in err
    assert "current allowed_actions: ['vulnerability scanning']" in err
