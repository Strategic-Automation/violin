"""Unit tests verifying core guard bug fixes and state hardening."""

from plugins.violin_guard import _on_session_reset_hook, command, state
from plugins.violin_guard.core.phases import Phase


def test_hypothesis_zero_parsing(tmp_path):
    """Verify hypothesis H-0 or '0' parses as '0' instead of being stripped to empty string."""
    hyp_file = tmp_path / "hypotheses.md"
    hyp_file.write_text(
        "# Hypotheses\n\n"
        "### H-0\n"
        "- Status: Formulated\n"
        "- Phase: VULN_RESEARCH\n"
        "- Target: 10.0.0.1\n"
        "- CVE Research: N/A\n"
        "- Exploit Research: N/A\n",
        encoding="utf-8",
    )

    res = command.check_hypothesis_freshness(
        eng_dir=tmp_path,
        phase=Phase.VULN_RESEARCH,
        command="nmap 10.0.0.1",
        primary_target="10.0.0.1",
        hypothesis_id="H-0",
    )
    assert not any("unlinked" in err.lower() for err in res.errors)


def test_read_json_non_existent_vs_error(tmp_path):
    """Verify read_json returns {} for non-existent file but raises on persistent read errors."""
    non_existent = tmp_path / "missing.json"
    assert state.read_json(non_existent) == {}

    existing = tmp_path / "existing.json"
    existing.write_text('{"key": "value"}', encoding="utf-8")
    assert state.read_json(existing) == {"key": "value"}


def test_resolve_eng_dir_defaults_to_cwd(tmp_path, monkeypatch):
    """Verify resolve_eng_dir resolves to CWD when scope markers are present."""
    monkeypatch.chdir(tmp_path)
    (tmp_path / "hypotheses.md").write_text("# Hypotheses\n", encoding="utf-8")
    assert state.resolve_eng_dir("") == tmp_path.resolve()
    assert state.resolve_eng_dir(".") == tmp_path.resolve()


def test_on_session_reset_hook_none_session_id():
    """Verify _on_session_reset_hook handles None session_id without throwing or raising KeyError."""
    _on_session_reset_hook(session_id=None, eng_dir=None)
