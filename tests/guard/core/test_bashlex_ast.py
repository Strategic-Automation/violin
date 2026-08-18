"""Unit tests for bashlex AST parsing and terminal policy classification."""

from plugins.violin_guard import bash_ast, terminal_policy


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
