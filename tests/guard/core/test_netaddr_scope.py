"""Unit tests for netaddr IPSet scope policy matching and yarl URL parsing."""

from pathlib import Path

import yaml

from plugins.violin_guard import targets


def test_normalize_target_yarl():
    assert targets.normalize_target("https://sub.example.com/api/v1") == "sub.example.com"
    assert targets.normalize_target("ws://10.0.0.5:8080/socket") == "10.0.0.5"
    assert targets.normalize_target("192.168.1.1") == "192.168.1.1"


def test_scope_ip_set_ranges_and_cidrs(tmp_path: Path):
    scope_file = tmp_path / "scope.yaml"
    scope_data = {
        "targets": {
            "ip_addresses": ["10.0.0.1", "192.168.1.0/24"],
            "ranges": ["172.16.0.10-172.16.0.20"],
        },
        "exclusions": {
            "ip_addresses": ["192.168.1.250"],
        },
    }
    scope_file.write_text(yaml.dump(scope_data), encoding="utf-8")

    # In-scope CIDR match
    res1 = targets.check_scope_targets(scope_file, "curl http://192.168.1.50")
    assert not res1.errors

    # In-scope Range match
    res2 = targets.check_scope_targets(scope_file, "curl http://172.16.0.15")
    assert not res2.errors

    # Excluded IP match inside in-scope CIDR
    res3 = targets.check_scope_targets(scope_file, "curl http://192.168.1.250")
    assert any("excluded target" in e for e in res3.errors)

    # Out of scope IP
    res4 = targets.check_scope_targets(scope_file, "curl http://10.99.99.99")
    assert any("out-of-scope" in e for e in res4.errors)
