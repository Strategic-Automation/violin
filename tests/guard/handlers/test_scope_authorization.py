from __future__ import annotations

from pathlib import Path

from plugins.violin_guard.core.engagement import bootstrap
from plugins.violin_guard.core.engagement.phases import Phase
from plugins.violin_guard.gates import command
from plugins.violin_guard.gates.command import check_scope_authorization, validate_scope


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


def test_scope_actions_reject_negations_and_containing_phrases() -> None:
    for value in ("no exploitation", "post-exploitation", "pre-exploitation-check"):
        result = check_scope_authorization(
            {
                "rules_of_engagement": {
                    "allowed_actions": [value],
                    "forbidden_actions": [],
                }
            },
            Phase.EXPLOITATION,
        )
        assert result.errors, value


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


def test_scope_denial_requires_operator_approval_for_amendment() -> None:
    scope = {"rules_of_engagement": {"allowed_actions": ["recon"]}}
    result = check_scope_authorization(scope, Phase.PRIVESC)

    assert result.errors
    message = " ".join(result.errors)
    assert "request operator approval" in message
    assert "do not widen your own scope" in message
    assert scope == {"rules_of_engagement": {"allowed_actions": ["recon"]}}


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


def test_command_scope_diagnostic_uses_canonical_path_without_mutation(tmp_path: Path) -> None:
    engagement = tmp_path / "engagement"
    assert bootstrap.init_engagement(engagement, host="10.10.10.10") == 0
    scope_path = engagement / "scope" / "scope.yaml"
    original_scope = scope_path.read_bytes()

    result = command.check_command(
        command.CheckCommandArgs(
            command="curl https://outside.example/status",
            phase="recon",
            eng_dir=str(engagement),
            target="10.10.10.10",
        )
    )

    assert any(str(scope_path.resolve()) in warning for warning in result.warnings)
    assert scope_path.read_bytes() == original_scope


def test_parenthetical_scope_actions_are_permitted() -> None:
    from plugins.violin_guard.core.engagement.phases import Phase
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
    from plugins.violin_guard.core.engagement.phases import Phase
    from plugins.violin_guard.gates.command import check_scope_authorization

    scope = {
        "rules_of_engagement": {
            "allowed_actions": ["vulnerability research"],
            "forbidden_actions": [],
        }
    }
    res = check_scope_authorization(scope, Phase.VULN_RESEARCH)
    assert not res.errors


def test_scope_authorization_error_message_provides_selection_list() -> None:
    from plugins.violin_guard.core.engagement.phases import Phase
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
    assert (
        "An approved amendment to rules_of_engagement.allowed_actions must explicitly authorize VULN_RESEARCH"
        in err
    )
    assert "'vulnerability research'" in err
    assert "'cve-research'" in err
    assert "current allowed_actions: ['vulnerability scanning']" in err
