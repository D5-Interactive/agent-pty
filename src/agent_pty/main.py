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
    clean_output,
    ensure_dirs,
    list_sessions,
    log_path,
    sock_path,
    state_path,
    strip_ansi,
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
    exact = [s for s in sessions if name in (s["id"], s.get("name"))]
    if exact:
        return exact[0]
    partial = [s for s in sessions if s["id"].startswith(name)]
    if len(partial) == 1:
        return partial[0]
    raise click.ClickException(f"no single session matches {name!r}")


def _slug(text: str) -> str:
    return "".join(c if c.isalnum() else "-" for c in text).strip("-")


def _session_id(name: str | None, user: str | None, host: str) -> str:
    base = _slug(name) if name else _slug(f"{user or 'ssh'}-{host}")
    return f"{base}-{uuid.uuid4().hex[:6]}"


def _rpc_or_fail(state: dict, op: str, wait: float | None = 15, **args) -> dict:
    response = _rpc(Path(state["socket"]), op, wait, **args)
    if not response.get("ok"):
        raise click.ClickException(response.get("error", "request failed"))
    return response


def _tail(path: Path, lines: int, raw: bool = False) -> str:
    with path.open("rb") as fh:
        fh.seek(0, os.SEEK_END)
        size = fh.tell()
        data = b""
        while size > 0 and data.count(b"\n") <= lines:
            step = min(8192, size)
            size -= step
            fh.seek(size)
            data = fh.read(step) + data
    text = clean_output(data.decode("utf-8", errors="replace"))
    if not raw:
        text = strip_ansi(text)
    return "\n".join(text.splitlines()[-lines:]) + ("\n" if text else "")


# ── CLI ──────────────────────────────────────────────────────────
@click.group(context_settings=CONTEXT)
@click.version_option(package_name="agent-pty")
def cli() -> None:
    """SSH into a machine with a full interactive PTY, held open in the background.

    Open a session once, then run commands, attach to the live shell, or move
    files to and from it from separate invocations. Commands run with exec
    share the shell's state: cd, exports and functions persist.
    """


@cli.command("connect")
@click.argument("host")
@click.option("-p", "--port", default=None, type=int, help="SSH port. Default 22 or ~/.ssh/config.")
@click.option("-u", "--user", default=None, help="Remote username. Default from ~/.ssh/config or $USER.")
@click.option("-i", "--key-file", default=None, help="SSH private key file.")
@click.option(
    "--password",
    default=None,
    help="SSH password. Prompted when neither password nor key is given.",
)
@click.option("--ttl", default=30, show_default=True, type=int, help="Idle timeout in minutes.")
@click.option("-n", "--name", default=None, help="Friendly session name.")
@click.option("--insecure", is_flag=True, help="Do not verify or record host keys.")
def connect(
    host: str,
    port: int,
    user: str | None,
    key_file: str | None,
    password: str | None,
    ttl: int,
    name: str | None,
    insecure: bool,
) -> None:
    """Open a background session with an interactive PTY on HOST.

    HOST is resolved through ~/.ssh/config when it has an entry, so aliases,
    IdentityFile, User and Port work without extra flags.
    """
    if not password and not key_file:
        if not sys.stdin.isatty():
            raise click.ClickException("provide --password or --key-file")
        password = click.prompt("SSH password", hide_input=True)

    ensure_dirs()
    session_id = _session_id(name, user, host)
    config = {
        "id": session_id,
        "name": name or session_id,
        "host": host,
        "port": port,
        "user": user,
        "password": password,
        "key_file": str(Path(key_file).expanduser()) if key_file else None,
        "insecure": insecure,
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
                target = f"{probe.get('user')}@{host}:{probe.get('port')}"
                click.echo(f"{session_id}\t{target}\tttl {ttl}m")
                return
        time.sleep(0.1)

    detail = ""
    with contextlib.suppress(OSError):
        detail = log_path(session_id).read_text(encoding="utf-8")[-800:]
    for leftover in (config_path, sock_path(session_id), state_path(session_id), log_path(session_id)):
        leftover.unlink(missing_ok=True)
    raise click.ClickException(f"could not start session\n{detail}".strip())


@cli.command("sessions")
@click.option("--json", "as_json", is_flag=True, help="Print the session list as JSON.")
def sessions_cmd(as_json: bool) -> None:
    """List live background sessions."""
    found = list_sessions(clean=True)
    if as_json:
        click.echo(json.dumps(found, indent=2))
        return
    if not found:
        click.echo("no live sessions")
        return
    rows = [("ID", "NAME", "TARGET", "PID", "IDLE", "STARTED", "TTL")]
    for state in found:
        probe = _rpc(Path(state["socket"]), "info", 1)
        idle = f"{probe['idle_seconds']}s" if probe.get("ok") else "-"
        rows.append(
            (
                state["id"],
                state.get("name", "-"),
                f"{state['user']}@{state['host']}:{state['port']}",
                str(state["pid"]),
                idle,
                state.get("started_at", "?"),
                f"{state.get('ttl', '?')}m",
            )
        )
    widths = [max(len(row[i]) for row in rows) for i in range(len(rows[0]))]
    for row in rows:
        click.echo("  ".join(cell.ljust(widths[i]) for i, cell in enumerate(row)).rstrip())


@cli.command("exec")
@click.option("-s", "--session", "name", default=None, help="Session id, name, or unique prefix.")
@click.option("--timeout", default=120.0, show_default=True, help="Seconds to wait for output.")
@click.argument("command", nargs=-1, required=True)
def exec_cmd(name: str | None, timeout: float, command: tuple[str, ...]) -> None:
    """Run COMMAND in the live PTY shell. Shell state persists across calls.

    The command's output is printed and its exit code becomes agent-pty's exit
    code. On timeout the command is interrupted and agent-pty exits 124.
    """
    state = _resolve(name)
    result = _rpc(
        Path(state["socket"]),
        "exec",
        timeout + 30,
        command=" ".join(command),
        timeout=timeout,
    )
    output = result.get("output") or ""
    if output:
        click.echo(output, nl=not output.endswith("\n"))
    if not result.get("ok"):
        if result.get("timed_out") or result.get("interrupted"):
            click.echo(f"agent-pty: {result.get('error', 'interrupted')}", err=True)
            sys.exit(int(result.get("exit_code", 124)))
        raise click.ClickException(result.get("error", "request failed"))
    sys.exit(int(result.get("exit_code", 0)))


@cli.command("shell")
@click.option("-s", "--session", "name", default=None, help="Session id, name, or unique prefix.")
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
        raise click.ClickException("attach refused: the session is running a command")
    sock.settimeout(None)

    fd = sys.stdin.fileno()
    saved = termios.tcgetattr(fd)
    tty.setraw(fd)
    last_size = (columns, rows)
    try:
        while True:
            ready, _, _ = select.select([sock, fd], [], [], 1.0)
            with contextlib.suppress(OSError):
                size = os.get_terminal_size()
                if (size.columns, size.lines) != last_size:
                    last_size = (size.columns, size.lines)
                    _rpc(Path(state["socket"]), "resize", 2, cols=size.columns, rows=size.lines)
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


@cli.command("logs")
@click.option("-s", "--session", "name", default=None, help="Session id, name, or unique prefix.")
@click.option("-n", "--lines", default=40, show_default=True, help="Lines to show.")
@click.option("-f", "--follow", is_flag=True, help="Keep printing new output.")
@click.option("--raw", is_flag=True, help="Keep terminal escape sequences.")
def logs_cmd(name: str | None, lines: int, follow: bool, raw: bool) -> None:
    """Show the PTY transcript of a session."""
    state = _resolve(name)
    path = Path(state.get("transcript") or "")
    if not path.is_file():
        raise click.ClickException("this session has no transcript yet")
    click.echo(_tail(path, lines, raw), nl=False)
    if not follow:
        return
    position = path.stat().st_size
    try:
        while True:
            with path.open("rb") as fh:
                fh.seek(position)
                chunk = fh.read()
            if chunk:
                text = clean_output(chunk.decode("utf-8", errors="replace"))
                click.echo(text if raw else strip_ansi(text), nl=False)
                position += len(chunk)
            time.sleep(0.25)
    except KeyboardInterrupt:
        return


@cli.command("upload")
@click.option("-s", "--session", "name", default=None, help="Session id, name, or unique prefix.")
@click.argument("local")
@click.argument("remote", required=False)
def upload(name: str | None, local: str, remote: str | None) -> None:
    """Upload a local FILE to the remote host."""
    state = _resolve(name)
    result = _rpc_or_fail(state, "upload", 3600, local=local, remote=remote, dir=False)
    click.echo(f"uploaded {local} -> {result['remote']}")


@cli.command("upload-dir")
@click.option("-s", "--session", "name", default=None, help="Session id, name, or unique prefix.")
@click.argument("local")
@click.argument("remote", required=False)
def upload_dir(name: str | None, local: str, remote: str | None) -> None:
    """Upload a local DIRECTORY tree to the remote host."""
    state = _resolve(name)
    result = _rpc_or_fail(state, "upload", 3600, local=local, remote=remote, dir=True)
    click.echo(f"uploaded {result['files']} file(s) -> {result['remote']}")


@cli.command("download")
@click.option("-s", "--session", "name", default=None, help="Session id, name, or unique prefix.")
@click.argument("remote")
@click.argument("local", required=False)
def download(name: str | None, remote: str, local: str | None) -> None:
    """Download a remote FILE."""
    state = _resolve(name)
    result = _rpc_or_fail(state, "download", 3600, remote=remote, local=local, dir=False)
    click.echo(f"downloaded {remote} -> {result['local']}")


@cli.command("download-dir")
@click.option("-s", "--session", "name", default=None, help="Session id, name, or unique prefix.")
@click.argument("remote")
@click.argument("local", required=False)
def download_dir(name: str | None, remote: str, local: str | None) -> None:
    """Download a remote DIRECTORY tree."""
    state = _resolve(name)
    result = _rpc_or_fail(state, "download", 3600, remote=remote, local=local, dir=True)
    click.echo(f"downloaded {result['files']} file(s) -> {result['local']}")


@cli.command("close")
@click.option("-s", "--session", "name", default=None, help="Session id, name, or unique prefix.")
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
@click.option("-s", "--session", "name", default=None, help="Session id, name, or unique prefix.")
@click.option("--json", "as_json", is_flag=True, help="Print the state as JSON.")
def info_cmd(name: str | None, as_json: bool) -> None:
    """Show one session's state."""
    state = _resolve(name)
    result = _rpc_or_fail(state, "info", 10)
    if as_json:
        click.echo(json.dumps(result, indent=2))
        return
    for key in ("id", "name", "host", "port", "user", "idle_seconds", "ttl", "attached", "running", "transcript"):
        click.echo(f"{key}: {result.get(key)}")
    for entry in result.get("forwards") or []:
        click.echo(f"forward {entry['id']}: -{entry['direction'][0].upper()} {entry['listen']} -> {entry['target']}")


@cli.command("send")
@click.option("-s", "--session", "name", default=None, help="Session id, name, or unique prefix.")
@click.option("--no-newline", is_flag=True, help="Send the text without a trailing newline.")
@click.argument("text")
def send_cmd(name: str | None, no_newline: bool, text: str) -> None:
    """Type TEXT into the live PTY shell."""
    state = _resolve(name)
    _rpc_or_fail(state, "write", 10, data=text if no_newline else text + "\n")
    click.echo("sent")


@cli.command("interrupt")
@click.option("-s", "--session", "name", default=None, help="Session id, name, or unique prefix.")
def interrupt_cmd(name: str | None) -> None:
    """Send Ctrl-C to the live PTY shell."""
    state = _resolve(name)
    _rpc_or_fail(state, "interrupt", 10)
    click.echo("interrupted")


@cli.command("rename")
@click.option("-s", "--session", "name", default=None, help="Session id, name, or unique prefix.")
@click.argument("new_name")
def rename_cmd(name: str | None, new_name: str) -> None:
    """Give a session a new name."""
    state = _resolve(name)
    result = _rpc_or_fail(state, "rename", 10, name=new_name)
    click.echo(f"renamed {state['id']} -> {result['name']}")


@cli.command("forward")
@click.option("-s", "--session", "name", default=None, help="Session id, name, or unique prefix.")
@click.option(
    "-L",
    "--local",
    "local_forwards",
    multiple=True,
    metavar="[BIND:]PORT:HOST:PORT",
    help="Listen locally and forward to the remote side.",
)
@click.option(
    "-R",
    "--remote",
    "remote_forwards",
    multiple=True,
    metavar="[BIND:]PORT:HOST:PORT",
    help="Listen on the remote side and forward to the local side.",
)
@click.option("--list", "list_forwards", is_flag=True, help="Show active forwards.")
@click.option("--remove", "remove_id", default=None, type=int, help="Remove a forward by id.")
def forward_cmd(
    name: str | None,
    local_forwards: tuple[str, ...],
    remote_forwards: tuple[str, ...],
    list_forwards: bool,
    remove_id: int | None,
) -> None:
    """Add, list, or remove SSH port forwards on a live session."""
    state = _resolve(name)
    if list_forwards:
        info = _rpc_or_fail(state, "info", 10)
        for entry in info.get("forwards") or []:
            click.echo(f"{entry['id']}\t-{entry['direction'][0].upper()}\t{entry['listen']}\t{entry['target']}")
        if not info.get("forwards"):
            click.echo("no forwards")
        return
    if remove_id is not None:
        _rpc_or_fail(state, "unforward", 10, id=remove_id)
        click.echo(f"removed forward {remove_id}")
        return
    for direction, specs in (("local", local_forwards), ("remote", remote_forwards)):
        for spec in specs:
            result = _rpc_or_fail(state, "forward", 20, direction=direction, spec=spec)
            click.echo(f"{result['id']}\t-{direction[0].upper()}\t{result['listen']}\t{result['target']}")
    if not local_forwards and not remote_forwards:
        raise click.ClickException("pass -L, -R, --list, or --remove")


def main() -> None:
    """Console entry point."""
    cli(prog_name="agent-pty")


if __name__ == "__main__":
    main()
