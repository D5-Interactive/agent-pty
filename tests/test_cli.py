"""Offline checks for CLI surface and PTY exec framing."""

import pytest
from click.testing import CliRunner

from agent_pty.main import _session_id, cli

COMMANDS = [
    "connect",
    "sessions",
    "exec",
    "shell",
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
        ("connect", ["HOST", "--port", "--user", "--key-file", "--password", "--ttl"]),
        ("exec", ["--session", "--timeout", "COMMAND"]),
        ("shell", ["--session"]),
        ("upload", ["--session", "LOCAL", "REMOTE"]),
        ("upload-dir", ["--session", "LOCAL", "REMOTE"]),
        ("download", ["--session", "REMOTE", "LOCAL"]),
        ("download-dir", ["--session", "REMOTE", "LOCAL"]),
        ("close", ["--session", "--all"]),
        ("info", ["--session"]),
    ],
)
def test_subcommand_help_covers_flags(command, flags):
    result = CliRunner().invoke(cli, [command, "--help"])
    assert result.exit_code == 0
    for flag in flags:
        assert flag in result.output


def test_session_id_is_socket_safe():
    session_id = _session_id("d5.dog", "host_name")
    assert session_id.startswith("d5-dog-host-name-")
    assert session_id.isascii()
    assert "/" not in session_id
