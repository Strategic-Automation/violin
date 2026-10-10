"""HTTP proof preflight agrees with the executor's existing normalization."""

import pytest

from plugins.violin_guard.core.engagement import bootstrap
from plugins.violin_guard.gates import command


@pytest.mark.parametrize(
    ("probe", "warns"),
    [
        ("curl -sS https://example.test/schema.json -o evidence/schema.json", False),
        ("curl -sS https://example.test/schema.json", False),
        ("curl -sS -i https://example.test/schema.json", False),
        ("curl -sS https://example.test/schema.json | python3 -c 'print(input())'", True),
        ("printf '%s' $( curl -sS https://example.test/schema.json )", True),
    ],
)
def test_http_preflight_preserves_authorization_input(tmp_path, monkeypatch, probe, warns):
    bootstrap.init_engagement(tmp_path, host="example.test")
    observed = []
    original = command.check_scope_targets

    def check_scope(scope_path, original_command, *args, **kwargs):
        observed.append(original_command)
        return original(scope_path, original_command, *args, **kwargs)

    monkeypatch.setattr(command, "check_scope_targets", check_scope)
    result = command.check_command(
        command.CheckCommandArgs(command=probe, phase="recon", eng_dir=str(tmp_path))
    )

    assert observed == [probe]
    proof_warnings = [warning for warning in result.warnings if "status observation" in warning]
    assert bool(proof_warnings) is warns
