from __future__ import annotations

from pathlib import Path

from plugins.violin_guard import bootstrap, command
from plugins.violin_guard.command import check_scope_authorization, validate_scope
from plugins.violin_guard.phases import Phase


def _scope(tmp_path: Path, targets: str, allowed: str = "recon") -> Path:
    path = tmp_path / "scope.yaml"
    path.write_text(
        f"""targets:
  {targets}
rules_of_engagement:
  allowed_actions: [{allowed}]
  forbidden_actions: []
engagement:
  date: 2026-08-01
authorized_parties: [operator]
authorisation:
  confirmed: true
""",
        encoding="utf-8",
    )
    return path


def test_domain_only_scope_is_valid(tmp_path: Path) -> None:
    result = validate_scope(_scope(tmp_path, "domains: [app.example.test]"))
    assert not any("ip_addresses" in error for error in result.errors)
    assert not result.errors


def test_url_only_scope_is_valid(tmp_path: Path) -> None:
    result = validate_scope(_scope(tmp_path, "urls: [https://app.example.test/login]"))
    assert not result.errors


def test_exploitation_is_not_blocked_by_post_exploitation_forbidden_action() -> None:
    result = check_scope_authorization(
        {
            "rules_of_engagement": {
                "allowed_actions": ["exploitation"],
                "forbidden_actions": ["post-exploitation"],
            }
        },
        Phase.EXPLOITATION,
    )
    assert not result.errors


def test_credential_stuffing_does_not_match_hydra_by_substring() -> None:
    result = check_scope_authorization(
        {
            "rules_of_engagement": {
                "allowed_actions": ["recon"],
                "forbidden_actions": ["credential-stuffing"],
            }
        },
        Phase.RECON,
    )
    assert not any("forbidden" in error for error in result.errors)


def test_runtime_command_rejects_scope_substitution(tmp_path: Path) -> None:
    engagement = tmp_path / "engagement"
    assert bootstrap.init_engagement(engagement, host="10.10.10.10") == 0
    result = command.check_command(
        command.CheckCommandArgs(
            command="echo local",
            phase="recon",
            eng_dir=str(engagement),
            scope=str(tmp_path / "other-scope.yaml"),
            target="10.10.10.10",
        )
    )
    assert any("canonical scope.yaml" in error for error in result.errors)
