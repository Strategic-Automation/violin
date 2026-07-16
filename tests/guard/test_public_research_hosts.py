from pathlib import Path

import yaml

from plugins.violin_guard.core.targets import check_scope_targets


def test_public_research_host_is_not_treated_as_an_assessment_target(tmp_path):
    scope = {"targets": {"ip_addresses": ["10.10.10.10"]}, "research_hosts": ["github.com"]}
    path = Path(tmp_path / "scope.yaml")
    path.write_text(yaml.safe_dump(scope), encoding="utf-8")

    result = check_scope_targets(path, "curl -L https://github.com/example/poc/raw/main/exploit.py")

    assert not result.errors


def test_unlisted_public_host_still_requires_review(tmp_path):
    scope = {"targets": {"ip_addresses": ["10.10.10.10"]}, "research_hosts": []}
    path = Path(tmp_path / "scope.yaml")
    path.write_text(yaml.safe_dump(scope), encoding="utf-8")

    assert check_scope_targets(path, "curl https://example.org/poc").warnings
