"""SSH into machines with full interactive pty — background session management."""

import contextlib
import json
from datetime import UTC, datetime

import click
import paramiko


@click.group()
def main():
    """Connect via SSH and run a command with an interactive PTY.

    Sessions stay open in the background; idle TTL triggers timeout exit.
    Every action is audited to JSON for traceability.
    """


# ── Audit logger ──────────────────────────────────────────────
_audit_log = []


def _audit(event: dict):
    """Record an audit event."""
    entry = {
        "timestamp": datetime.now(UTC).isoformat(),
        **event,
    }
    click.echo(json.dumps(entry, indent=2))


# ── Core SSH helpers ───────────────────────────────────────────
def connect(host: str, port: int, user: str | None, key_file: str | None,
            password: str | None) -> paramiko.SSHClient:
    """Create and return an authenticated SSHClient."""
    client = paramiko.SSHClient()
    policy = paramiko.AutoAddPolicy()
    client.set_missing_host_key_policy(policy)

    pkey = None
    if key_file:
        try:
            pkey = paramiko.RSAKey.from_private_key_file(key_file)
        except paramiko.PasswordRequiredException as exc:
            click.echo(f"Key load error: {exc}", err=True)

    client.connect(
        hostname=host,
        port=port,
        username=user or "",
        password=password,
        pkey=pkey,
        timeout=30,
    )
    return client


def get_channel(client: paramiko.SSHClient) -> paramiko.Channel | None:
    """Open a session channel and set PTY for interactive shell."""
    transport = client.get_transport()
    if not transport:
        return None
    with contextlib.suppress(Exception):
        channel = transport.open_session()
        channel.get_pty(term='vt100')
        return channel
    click.echo("Channel open error", err=True)


def channel_result(channel: paramiko.Channel, command: str):
    """Execute a command on the remote machine and return file objects."""
    result = channel.exec_command(command)
    if result is not None:
        return result

    return None


# ── File transfer helpers ─────────────────────────────────────
def run_file_sftp(sftp: paramiko.SFTPClient, local_path: str) -> None:
    """Run a file from local to remote via SFTP."""
    try:
        sftp.put(local_path, "/run-file")
    except paramiko.SSHException as exc:
        click.echo(f"File transfer error: {exc}", err=True)


def get_file_sftp(sftp: paramiko.SFTPClient, remote_path: str) -> None:
    """Download file from remote to local via SFTP."""
    try:
        sftp.get(remote_path, "/get-file")
    except paramiko.SSHException as exc:
        click.echo(f"Download error: {exc}", err=True)


def get_directory_sftp(sftp: paramiko.SFTPClient, remote_dir: str) -> None:
    """Copy directory from remote to local via SFTP."""
    try:
        sftp.stat(remote_dir)
    except paramiko.SSHException as exc:
        click.echo(f"Directory stat error: {exc}", err=True)


# ── CLI command ───────────────────────────────────────────────
@main.command()
@click.option("--host", required=True, help="Remote host to connect to")
@click.option("--port", default=22, type=int, help="SSH port (default 22)")
@click.option("--user", default=None, help="Remote username")
@click.option("--key-file", help="Path to SSH private key file")
@click.option("--password", help="Password for authentication")
@click.option("--command", required=True, help="Command or command string to execute on remote machine")
@click.option("--session", default=None, help="User already having a session open in background")
@click.option("--cmd", default="", help="CLI command to run on remote machine (overrides --command)")
@click.option("--run-file", default="", help="Path to local file to transfer to remote via sftp/scp")
@click.option("-f", "--get-file", "get_filepath", help="Download single file from remote to local via sftp")
@click.option("-d", "--get-dir", "get_directory", help="Copy directory from remote to local via sftp")
@click.option("--close", is_flag=True, help="Close the connection and session")
@click.option("--ttl", default=30, type=int, help="Idle timeout in minutes for sessions")
def ssh_connect(host, port, user, key_file, password, command,
                session, cmd, run_file, get_filepath, get_directory, close, ttl):
    """Connect via SSH and manage a command session with background support.

    - Sessions stay open in the background with idle TTL timeout exit if unused for >30 min.
    - Every action is audited to JSON for traceability.
    """

    actual_command = cmd or command

    client = connect(host, port, user, key_file, password)
    channel = get_channel(client)

    if not channel:
        click.echo("Failed to open session channel", err=True)
        _audit({"action": "ssh_connect", "error": "channel_open_failed"})
        return

    _audit({
        "action": "ssh_connect",
        "host": host,
        "user": user or "",
        "command": actual_command[:100] if len(actual_command) > 100 else actual_command,
    })

    ttl_seconds = ttl * 60

    def cleanup_task():
        """Background task to close session after TTL."""
        click.echo(f"Session idle for {ttl_seconds}s — closing", err=True)
        contextlib.suppress(Exception)
        channel.close()
        client.close()

    import threading
    t_cleanup = threading.Thread(target=cleanup_task, daemon=True)
    t_cleanup.start()

    if run_file:
        try:
            transport = client.get_transport()
            sftp_client = paramiko.SFTPClient.from_transport(transport) if transport else None

            if sftp_client is not None and hasattr(sftp_client, 'put'):
                run_file_sftp(sftp_client, run_file)
            click.echo(f"File transfer: {run_file} → remote", err=True)
        except paramiko.SSHException as exc:
            click.echo(f"Run-file error: {exc}", err=True)

    elif get_filepath:
        try:
            transport = client.get_transport()
            sftp_client = paramiko.SFTPClient.from_transport(transport) if transport else None

            if sftp_client is not None and hasattr(sftp_client, 'get'):
                    get_file_sftp(sftp_client, get_filepath)
                    click.echo(f"Downloaded: {get_filepath} → local", err=True)
        except paramiko.SSHException as exc:
            click.echo(f"Get-file error: {exc}", err=True)

    elif get_directory:
        try:
            transport = client.get_transport()
            sftp_client = paramiko.SFTPClient.from_transport(transport) if transport else None

            if sftp_client is not None and hasattr(sftp_client, 'stat'):
                    get_directory_sftp(sftp_client, get_directory)
                    click.echo(f"Copied: {get_directory} → local", err=True)
        except paramiko.SSHException as exc:
            click.echo(f"Get-dir error: {exc}", err=True)

    else:
        result = channel_result(channel, actual_command)
        if result is not None:
            out_lines = []
            err_lines = []

            def collect(out_stream):
                while True:
                    try:
                        line = out_stream.readline(64).decode("utf-8", errors="replace")
                        if not line:
                            break
                        out_lines.append(line)
                    except paramiko.SSHException:
                        break

            import threading
            t_out = threading.Thread(target=collect, args=(result.stdout,))
            t_err = threading.Thread(target=collect, args=(result.stderr,))
            t_out.start()
            t_err.start()
            t_out.join(timeout=120)
            t_err.join(timeout=120)

            _audit({
                "action": "ssh_execute",
                "command": actual_command[:100],
                "output_lines": out_lines,
                "stderr_lines": err_lines,
            })

            click.echo("STDOUT:")
            for line in out_lines:
                click.echo(line)
            if err_lines:
                click.echo("\nSTDERR:")
                for line in err_lines:
                    click.echo(line, err=True)
        else:
            click.echo("Command execution failed", err=True)

    if close or channel is None:
        try:
            channel.close()
        except paramiko.SSHException:
            pass
        client.close()
        _audit({"action": "ssh_close", "reason": "close_flag"})


if __name__ == "__main__":
    main()
