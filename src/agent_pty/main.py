"""agent-pty: SSH with persistent, background PTY sessions."""

from __future__ import annotations

import contextlib
import json
import os
import select
import socket
import subprocess
import sys
import termios
import time
import tty
import uuid
from pathlib import Path

import click

from .session import (
    SESSIONS_DIR,
    ensure_dirs,
    list_sessions,
    log_path,
    sock_path,
    state_path,
)

CONTEXT = {"help_option_names": ["-h", "--help"]}


# ── client transport ─────────────────────────────────────────────
def _rpc(path: Path, op: str, wait: float | None = 15, **args) -> dict:
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.settimeout(wait)
    try:
        sock.connect(str(path))
        sock.sendall(json.dumps({"op": op, "args": args}).encode() + b"\n")
        return json.loads(_recv_line(sock))
    except (OSError, ValueError) as exc:
        return {"ok": False, "error": str(exc)}
    finally:
        sock.close()


def _recv_line(sock: socket.socket) -> str:
    chunks = bytearray()
    while b"\n" not in chunks:
        chunk = sock.recv(65536)
        if not chunk:
            break
        chunks.extend(chunk)
    return bytes(chunks).split(b"\n", 1)[0].decode("utf-8", errors="replace")


def _resolve(name: str | None) -> dict:
    sessions = list_sessions(clean=True)
    if not sessions:
        raise click.ClickException("no live sessions; run 'agent-pty connect HOST' first")
    if not name:
        if len(sessions) > 1:
            names = ", ".join(s["id"] for s in sessions)
            raise click.ClickException(f"several sessions live ({names}); pick one with -s")
        return sessions[0]
    exact = [s for s in sessions if s["id"] == name]
    if exact:
        return exact[0]
    partial = [s for s in sessions if s["id"].startswith(name)]
    if len(partial) == 1:
        return partial[0]
    raise click.ClickException(f"no single session matches {name!r}")


def _session_id(user: str, host: str) -> str:
    slug = "".join(c if c.isalnum() else "-" for c in f"{user}-{host}").strip("-")
    return f"{slug}-{uuid.uuid4().hex[:6]}"


def _rpc_or_fail(state: dict, op: str, wait: float | None = 15, **args) -> dict:
    response = _rpc(Path(state["socket"]), op, wait, **args)
    if not response.get("ok"):
        raise click.ClickException(response.get("error", "request failed"))
    return response


# ── CLI ──────────────────────────────────────────────────────────
@click.group(context_settings=CONTEXT)
@click.version_option(package_name="agent-pty")
def cli() -> None:
    """SSH into a machine with a full interactive PTY, held open in the background.

    Open a session once, then run commands, attach to the live shell, or move
    files to and from it from separate invocations.
    """


@cli.command("connect")
@click.argument("host")
@click.option("-p", "--port", default=22, show_default=True, help="SSH port.")
@click.option("-u", "--user", default=None, help="Remote username.")
@click.option("-i", "--key-file", default=None, help="SSH private key file.")
@click.option(
    "--password",
    default=None,
    help="SSH password. Prompted when neither password nor key is given.",
)
@click.option("--ttl", default=30, show_default=True, type=int, help="Idle timeout in minutes.")
def connect(host: str, port: int, user: str | None, key_file: str | None, password: str | None, ttl: int) -> None:
    """Open a background session with an interactive PTY on HOST."""
    user = user or os.environ.get("USER") or "root"
    if not password and not key_file:
        if not sys.stdin.isatty():
            raise click.ClickException("provide --password or --key-file")
        password = click.prompt("SSH password", hide_input=True)

    ensure_dirs()
    session_id = _session_id(user, host)
    config = {
        "id": session_id,
        "host": host,
        "port": port,
        "user": user,
        "password": password,
        "key_file": str(Path(key_file).expanduser()) if key_file else None,
        "ttl": ttl,
    }
    config_path = SESSIONS_DIR / f"{session_id}.cfg"
    config_path.write_text(json.dumps(config), encoding="utf-8")
    os.chmod(config_path, 0o600)

    with log_path(session_id).open("ab") as log:
        proc = subprocess.Popen(  # noqa: S603
            [sys.executable, "-m", "agent_pty.session", str(config_path)],
            stdin=subprocess.DEVNULL,
            stdout=log,
            stderr=subprocess.STDOUT,
            start_new_session=True,
            close_fds=True,
        )

    deadline = time.time() + 40
    while time.time() < deadline:
        if proc.poll() is not None:
            break
        if sock_path(session_id).exists():
            probe = _rpc(sock_path(session_id), "info", 2)
            if probe.get("ok"):
                click.echo(f"{session_id}\t{user}@{host}:{port}\tttl {ttl}m")
                return
        time.sleep(0.1)

    detail = ""
    with contextlib.suppress(OSError):
        detail = log_path(session_id).read_text(encoding="utf-8")[-800:]
    for leftover in (config_path, sock_path(session_id), state_path(session_id), log_path(session_id)):
        leftover.unlink(missing_ok=True)
    raise click.ClickException(f"could not start session\n{detail}".strip())


@cli.command("sessions")
def sessions_cmd() -> None:
    """List live background sessions."""
    found = list_sessions(clean=True)
    if not found:
        click.echo("no live sessions")
        return
    rows = [("ID", "TARGET", "PID", "STARTED", "TTL")]
    for state in found:
        rows.append(
            (
                state["id"],
                f"{state['user']}@{state['host']}:{state['port']}",
                str(state["pid"]),
                state.get("started_at", "?"),
                f"{state.get('ttl', '?')}m",
            )
        )
    widths = [max(len(row[i]) for row in rows) for i in range(len(rows[0]))]
    for row in rows:
        click.echo("  ".join(cell.ljust(widths[i]) for i, cell in enumerate(row)).rstrip())


@cli.command("exec")
@click.option("-s", "--session", "name", default=None, help="Session id or unique prefix.")
@click.option("--timeout", default=120.0, show_default=True, help="Seconds to wait for output.")
@click.argument("command", nargs=-1, required=True)
def exec_cmd(name: str | None, timeout: float, command: tuple[str, ...]) -> None:
    """Run COMMAND on the session's connection and print its output.

    The remote exit code becomes agent-pty's exit code.
    """
    state = _resolve(name)
    result = _rpc_or_fail(state, "exec", timeout + 30, command=" ".join(command), timeout=timeout)
    if result.get("output"):
        click.echo(result["output"], nl=not result["output"].endswith("\n"))
    if result.get("stderr"):
        click.echo(result["stderr"], err=True, nl=not result["stderr"].endswith("\n"))
    sys.exit(int(result.get("exit_code", 0)))


@cli.command("shell")
@click.option("-s", "--session", "name", default=None, help="Session id or unique prefix.")
def shell(name: str | None) -> None:
    """Attach to the live PTY. Press Ctrl-] to detach without closing it."""
    state = _resolve(name)
    if not sys.stdin.isatty():
        raise click.ClickException("shell needs a TTY")
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.settimeout(10)
    try:
        sock.connect(state["socket"])
    except OSError as exc:
        raise click.ClickException(str(exc)) from exc
    columns, rows = os.get_terminal_size()
    sock.sendall(json.dumps({"op": "attach", "args": {"cols": columns, "rows": rows}}).encode() + b"\n")
    if not json.loads(_recv_line(sock)).get("ok"):
        raise click.ClickException("attach refused")
    sock.settimeout(None)

    fd = sys.stdin.fileno()
    saved = termios.tcgetattr(fd)
    tty.setraw(fd)
    try:
        while True:
            ready, _, _ = select.select([sock, fd], [], [], 1.0)
            if sock in ready:
                data = sock.recv(65536)
                if not data:
                    break
                sys.stdout.buffer.write(data)
                sys.stdout.buffer.flush()
            if fd in ready:
                data = os.read(fd, 4096)
                if not data or b"\x1d" in data:
                    sock.sendall(data.split(b"\x1d", 1)[0])
                    break
                sock.sendall(data)
    except OSError as exc:
        click.echo(f"\r\nconnection error: {exc}", err=True)
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, saved)
        sock.close()
    click.echo("\r\n[detached]")


@cli.command("upload")
@click.option("-s", "--session", "name", default=None, help="Session id or unique prefix.")
@click.argument("local")
@click.argument("remote", required=False)
def upload(name: str | None, local: str, remote: str | None) -> None:
    """Upload a local FILE to the remote host."""
    state = _resolve(name)
    result = _rpc_or_fail(state, "upload", 3600, local=local, remote=remote, dir=False)
    click.echo(f"uploaded {local} -> {result['remote']}")


@cli.command("upload-dir")
@click.option("-s", "--session", "name", default=None, help="Session id or unique prefix.")
@click.argument("local")
@click.argument("remote", required=False)
def upload_dir(name: str | None, local: str, remote: str | None) -> None:
    """Upload a local DIRECTORY tree to the remote host."""
    state = _resolve(name)
    result = _rpc_or_fail(state, "upload", 3600, local=local, remote=remote, dir=True)
    click.echo(f"uploaded {result['files']} file(s) -> {result['remote']}")


@cli.command("download")
@click.option("-s", "--session", "name", default=None, help="Session id or unique prefix.")
@click.argument("remote")
@click.argument("local", required=False)
def download(name: str | None, remote: str, local: str | None) -> None:
    """Download a remote FILE."""
    state = _resolve(name)
    result = _rpc_or_fail(state, "download", 3600, remote=remote, local=local, dir=False)
    click.echo(f"downloaded {remote} -> {result['local']}")


@cli.command("download-dir")
@click.option("-s", "--session", "name", default=None, help="Session id or unique prefix.")
@click.argument("remote")
@click.argument("local", required=False)
def download_dir(name: str | None, remote: str, local: str | None) -> None:
    """Download a remote DIRECTORY tree."""
    state = _resolve(name)
    result = _rpc_or_fail(state, "download", 3600, remote=remote, local=local, dir=True)
    click.echo(f"downloaded {result['files']} file(s) -> {result['local']}")


@cli.command("close")
@click.option("-s", "--session", "name", default=None, help="Session id or unique prefix.")
@click.option("--all", "close_all", is_flag=True, help="Close every live session.")
def close(name: str | None, close_all: bool) -> None:
    """Close a session and its SSH connection."""
    targets = list_sessions(clean=True) if close_all else [_resolve(name)]
    if not targets:
        click.echo("no live sessions")
        return
    for state in targets:
        _rpc(Path(state["socket"]), "close", 10)
        click.echo(f"closed {state['id']}")


@cli.command("info")
@click.option("-s", "--session", "name", default=None, help="Session id or unique prefix.")
def info_cmd(name: str | None) -> None:
    """Show one session's state."""
    state = _resolve(name)
    result = _rpc_or_fail(state, "info", 10)
    for key in ("id", "host", "port", "user", "idle_seconds", "ttl", "attached"):
        click.echo(f"{key}: {result.get(key)}")


def main() -> None:
    """Console entry point."""
    cli(prog_name="agent-pty")


if __name__ == "__main__":
    main()
