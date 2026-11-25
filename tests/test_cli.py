"""Offline checks for the CLI surface, exec framing, transfers and forwards."""

import json
import os
import socket
import sys

import pytest
from click.testing import CliRunner

from agent_pty import session as session_module
from agent_pty.main import _resolve, _session_id, cli
from agent_pty.session import (
    clean_output,
    parse_cwd,
    parse_dynamic,
    parse_exec,
    parse_forward,
    parse_jump,
    parse_partial,
    prune_artifacts,
    pty_payload,
    strip_ansi,
)

COMMANDS = [
    "connect",
    "sessions",
    "exec",
    "shell",
    "logs",
    "send",
    "interrupt",
    "rename",
    "forward",
    "prune",
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
        ("send", ["--session", "--no-newline", "TEXT"]),
        ("interrupt", ["--session"]),
        ("rename", ["--session", "NEW_NAME"]),
        ("forward", ["--session", "--local", "--remote", "--dynamic", "--list", "--remove"]),
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
    assert "APTYabc12345C%s" in payload and '"$PWD"' in payload


def test_parse_cwd_reads_the_directory_marker():
    nonce = "abc12345"
    buf = f"\x1eAPTY{nonce}E0\x1e\x1eAPTY{nonce}C/srv/app\x1e"
    assert parse_cwd(buf, nonce) == "/srv/app"
    assert parse_cwd("nothing", nonce) is None


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


def test_strip_ansi_removes_exec_markers():
    assert strip_ansi("a\x1eAPTYdeadbeefB\x1eb\x1eAPTYdeadbeefE0\x1ec") == "abc"


@pytest.mark.parametrize(
    ("spec", "expected"),
    [
        ("8080:localhost:80", ("127.0.0.1", 8080, "localhost", 80)),
        ("10.1.2.3:9000:db:5432", ("10.1.2.3", 9000, "db", 5432)),
        ("2222:host:22", ("127.0.0.1", 2222, "host", 22)),
    ],
)
def test_parse_forward(spec, expected):
    assert parse_forward(spec) == expected


@pytest.mark.parametrize("spec", ["8080", "a:b:c:d:e", "x:y:z"])
def test_parse_forward_rejects_bad_specs(spec):
    with pytest.raises(ValueError):
        parse_forward(spec)


@pytest.mark.parametrize(
    ("spec", "expected"),
    [
        ("1080", ("127.0.0.1", 1080)),
        ("10.0.0.5:1080", ("10.0.0.5", 1080)),
        ("1080", ("127.0.0.1", 1080)),
    ],
)
def test_parse_dynamic(spec, expected):
    assert parse_dynamic(spec) == expected


@pytest.mark.parametrize("spec", ["1:2:3:4:5", "x:y:z:w", "1080:host:99999"])
def test_parse_forward_rejects_bad_ports(spec):
    with pytest.raises(ValueError):
        parse_forward(spec)


def test_resolve_refuses_duplicate_names(monkeypatch):
    live = [
        {"id": "a-111111", "name": "web", "socket": "a.sock"},
        {"id": "b-222222", "name": "web", "socket": "b.sock"},
    ]
    monkeypatch.setattr(sys.modules["agent_pty.main"], "list_sessions", lambda clean=False: live)
    with pytest.raises(Exception, match="several sessions are named"):
        _resolve("web")
    assert _resolve("a-111111")["id"] == "a-111111"


def test_prune_keeps_live_sessions_and_drops_dead_ones(monkeypatch, tmp_path):
    monkeypatch.setattr(session_module, "SESSIONS_DIR", tmp_path)
    for session_id, pid in (("live-1", os.getpid()), ("dead-1", 999999)):
        (tmp_path / f"{session_id}.json").write_text(json.dumps({"id": session_id, "pid": pid}))
        for suffix in ("sock", "out", "log"):
            (tmp_path / f"{session_id}.{suffix}").write_text("x")
    orphan = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    orphan.bind(str(tmp_path / "dead-2.sock"))
    removed = prune_artifacts()
    orphan.close()
    assert not (tmp_path / "dead-1.json").exists()
    assert not (tmp_path / "dead-1.out").exists()
    assert not (tmp_path / "dead-2.sock").exists()
    assert (tmp_path / "live-1.json").exists()
    assert (tmp_path / "live-1.out").exists()
    assert removed == 5


def test_parse_forward_and_dynamic_accept_ipv6():
    assert parse_forward("[::1]:8080:[2001:db8::5]:22") == ("::1", 8080, "2001:db8::5", 22)
    assert parse_dynamic("[::1]:1080") == ("::1", 1080)


@pytest.mark.parametrize(
    ("spec", "expected"),
    [
        ("d5dog", (None, "d5dog", None)),
        ("deploy@d5dog:2222", ("deploy", "d5dog", 2222)),
        ("[::1]:2222", (None, "::1", 2222)),
    ],
)
def test_parse_jump(spec, expected):
    assert parse_jump(spec) == expected


@pytest.mark.parametrize("spec", ["user@", "[::1]:0", "host:99999", "a:b:c:d"])
def test_parse_jump_rejects_bad_specs(spec):
    with pytest.raises(ValueError):
        parse_jump(spec)


def test_session_id_is_socket_safe():
    session_id = _session_id(None, "d5.dog", "host_name")
    assert session_id.startswith("d5-dog-host-name-")
    assert session_id.isascii()
    assert "/" not in session_id
    assert _session_id("web box", "u", "h").startswith("web-box-")
