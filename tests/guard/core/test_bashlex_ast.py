"""Unit tests for bashlex AST parsing and terminal policy classification."""

from plugins.violin_guard.core.commands import bash_ast
from plugins.violin_guard.gates import terminal_policy


def test_parse_bash_segments_simple():
    segments = bash_ast.parse_bash_segments("echo 'hello' && ls -la")
    assert len(segments) == 2
    assert segments[0].executable == "echo"
    assert segments[1].executable == "ls"


def test_parse_bash_segments_pipeline():
    segments = bash_ast.parse_bash_segments("cat /tmp/foo | grep bar")
    assert len(segments) == 2
    assert segments[0].executable == "cat"
    assert segments[1].executable == "grep"


def test_extract_all_command_words_subshell():
    words = bash_ast.extract_all_command_words("echo $(cat target.txt)")
    assert "echo" in words
    assert "cat" in words
    assert "target.txt" in words


def test_block_terminal_command_target_in_subshell():
    # Subshell containing an IP address must be detected and blocked
    cmd = "echo $(nmap 192.168.1.50)"
    msg = terminal_policy.block_terminal_command(cmd)
    assert msg is not None
    assert "target host literal detected" in msg


def test_block_terminal_command_target_in_pipeline():
    cmd = "cat targets.txt | nc 10.0.0.5 4444"
    msg = terminal_policy.block_terminal_command(cmd)
    assert msg is not None
    assert "target host literal detected" in msg


def test_block_terminal_command_local_pipeline_allowed():
    cmd = "cat /var/log/syslog | grep error | head -n 10"
    msg = terminal_policy.block_terminal_command(cmd)
    assert msg is None


def test_declared_parse_errors_cover_every_bashlex_failure():
    """The narrow except tuple must cover what bashlex actually raises."""
    for bad in ("echo 'unterminated", "if then fi(", "echo $(((", "echo $((1+1))"):
        try:
            bash_ast.bashlex.parse(bad)
        except Exception as exc:
            assert isinstance(exc, bash_ast._BASH_PARSE_ERRORS), (bad, type(exc))


def test_arithmetic_expansion_falls_back_instead_of_raising():
    """$((...)) is complete shell, but bashlex raises NotImplementedError for it.

    It must take the same best-effort fallback as a syntax error: otherwise the
    command aborts the caller instead of being classified.
    """
    command = 'for i in 1 2 3; do n=$((i+1)); curl -sS "https://target.test/a/$n"; done'
    words = bash_ast.extract_all_command_words(command)
    assert "curl" in words
    segments = bash_ast.parse_bash_segments(command)
    assert any(segment.executable == "curl" for segment in segments)


def test_unparseable_command_falls_back_to_naive_split(monkeypatch):
    """A parser failure must still yield a best-effort segment, not an exception."""

    def boom(_command: str):
        raise bash_ast._BASH_PARSE_ERRORS[0]("unparseable", "", 0)

    monkeypatch.setattr(bash_ast.bashlex, "parse", boom)
    segments = bash_ast.parse_bash_segments("echo 'unterminated")
    assert [segment.executable for segment in segments] == ["echo"]
