"""Offline checks for the CLI surface and PTY exec framing."""

import pytest
from click.testing import CliRunner

from agent_pty.main import _session_id, cli
from agent_pty.session import clean_output, parse_exec, parse_partial, pty_payload, strip_ansi

COMMANDS = [
    "connect",
    "sessions",
    "exec",
    "shell",
    "logs",
    "upload",
    "upload-dir",
    "download",
    "download-dir",
    "close",
    "info",
]


def test_help_lists_every_command():
    result = CliRunner().invoke(cli, ["--help"])
    assert result.exit_code == 0
    for command in COMMANDS:
        assert command in result.output


@pytest.mark.parametrize(
    ("command", "flags"),
    [
        ("connect", ["HOST", "--port", "--user", "--key-file", "--password", "--ttl", "--name", "--insecure"]),
        ("sessions", ["--json"]),
        ("exec", ["--session", "--timeout", "COMMAND"]),
        ("shell", ["--session"]),
        ("logs", ["--session", "--lines", "--follow", "--raw"]),
        ("upload", ["--session", "LOCAL", "REMOTE"]),
        ("upload-dir", ["--session", "LOCAL", "REMOTE"]),
        ("download", ["--session", "REMOTE", "LOCAL"]),
        ("download-dir", ["--session", "REMOTE", "LOCAL"]),
        ("close", ["--session", "--all"]),
        ("info", ["--session", "--json"]),
    ],
)
def test_subcommand_help_covers_flags(command, flags):
    result = CliRunner().invoke(cli, [command, "--help"])
    assert result.exit_code == 0
    for flag in flags:
        assert flag in result.output


def test_pty_payload_brackets_the_command_in_one_group():
    payload = pty_payload("echo hi", "abc12345")
    assert payload.startswith("{ printf '\\036APTYabc12345B\\036'\n")
    assert "echo hi\n" in payload
    assert payload.rstrip().endswith("}")
    assert payload.count("\\036APTYabc12345B\\036") == 1
    assert payload.count("\\036APTYabc12345E%s\\036") == 1


def test_parse_exec_ignores_prompt_and_echo():
    nonce = "abc12345"
    buf = (
        "\x1b]0;d5dog:~\x07prompt% { printf '\\036APTYabc12345B\\036'\r\n"
        "> echo hi\r\n"
        "\x1eAPTYabc12345B\x1e"
        "hello\r\nworld\r\n"
        "\x1eAPTYabc12345E0\x1e\r\n"
        "prompt% "
    )
    assert parse_exec(buf, nonce) == ("hello\r\nworld\r\n", 0)


def test_parse_exec_reports_failure_code():
    nonce = "deadbeef"
    buf = f"noise\x1eAPTY{nonce}B\x1e\x1eAPTY{nonce}E42\x1e"
    assert parse_exec(buf, nonce) == ("", 42)


def test_parse_exec_waits_for_end_marker():
    assert parse_exec("still running", "abc12345") is None


def test_parse_partial_returns_interrupted_output():
    nonce = "feedface"
    buf = f"junk\x1eAPTY{nonce}B\x1epartial line\r\n"
    assert parse_partial(buf, nonce) == "partial line\r\n"


def test_parse_partial_stops_at_the_interrupt_and_prompt():
    nonce = "feedface"
    buf = f"\x1eAPTY{nonce}B\x1epartial\r\n^Cprompt% "
    assert parse_partial(buf, nonce) == "partial\r\n"


def test_clean_output_normalizes_carriage_returns():
    assert clean_output("a\r\nb\rc") == "a\nb\nc"


def test_strip_ansi_removes_escapes_and_control_bytes():
    raw = "\x1b]2;title\x07\x1b[34mhello\x1b[00m\x00world\x1b[K"
    assert strip_ansi(raw) == "helloworld"


def test_session_id_is_socket_safe():
    session_id = _session_id(None, "d5.dog", "host_name")
    assert session_id.startswith("d5-dog-host-name-")
    assert session_id.isascii()
    assert "/" not in session_id
    assert _session_id("web box", "u", "h").startswith("web-box-")
