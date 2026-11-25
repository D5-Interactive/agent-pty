"""Persistent SSH PTY sessions and the local daemon that owns them."""

from __future__ import annotations

import base64
import contextlib
import json
import os
import posixpath
import re
import select
import shlex
import socket
import stat
import sys
import threading
import time
import uuid
from datetime import UTC, datetime
from pathlib import Path

import paramiko

HOME = Path(os.environ.get("AGENT_PTY_HOME", str(Path.home() / ".agent-pty")))
SESSIONS_DIR = HOME / "sessions"
AUDIT_LOG = HOME / "audit.jsonl"
KNOWN_HOSTS = HOME / "known_hosts"
BUFFER_LIMIT = 1_048_576
_audit_lock = threading.Lock()

_MARK_B = "\x1eAPTY{n}B\x1e"
_MARK_E = "\x1eAPTY{n}E"


# ── paths, state, audit ──────────────────────────────────────────
def ensure_dirs() -> None:
    HOME.mkdir(parents=True, exist_ok=True)
    SESSIONS_DIR.mkdir(parents=True, exist_ok=True)
    for path in (HOME, SESSIONS_DIR):
        os.chmod(path, 0o700)
    for path in (AUDIT_LOG, KNOWN_HOSTS):
        with contextlib.suppress(OSError):
            path.touch(exist_ok=True)
            os.chmod(path, 0o600)


def state_path(session_id: str) -> Path:
    return SESSIONS_DIR / f"{session_id}.json"


def sock_path(session_id: str) -> Path:
    return SESSIONS_DIR / f"{session_id}.sock"


def log_path(session_id: str) -> Path:
    return SESSIONS_DIR / f"{session_id}.log"


def transcript_path(session_id: str) -> Path:
    return SESSIONS_DIR / f"{session_id}.out"


def audit(session_id: str, action: str, **fields) -> None:
    ensure_dirs()
    entry = {
        "timestamp": datetime.now(UTC).isoformat(),
        "session": session_id,
        "action": action,
        **fields,
    }
    with _audit_lock, AUDIT_LOG.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(entry) + "\n")


def pid_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except OSError:
        return False
    return True


def read_state(session_id: str) -> dict | None:
    try:
        return json.loads(state_path(session_id).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def list_sessions(clean: bool = False) -> list[dict]:
    """Live sessions, oldest first. Removes files left by dead daemons."""
    if not SESSIONS_DIR.is_dir():
        return []
    sessions = []
    for path in sorted(SESSIONS_DIR.glob("*.json")):
        state = read_state(path.stem)
        if state and pid_alive(state.get("pid", 0)):
            sessions.append(state)
        elif clean:
            for leftover in (state_path(path.stem), sock_path(path.stem)):
                leftover.unlink(missing_ok=True)
    return sorted(sessions, key=lambda s: s.get("started_at", ""))


_ARTIFACT_SUFFIXES = {"json", "sock", "log", "out", "cfg", "tmp"}


def prune_artifacts() -> int:
    """Delete files belonging to dead sessions. Returns the count removed."""
    if not SESSIONS_DIR.is_dir():
        return 0
    removed = 0
    for path in SESSIONS_DIR.iterdir():
        if path.is_dir() or path.suffix.lstrip(".") not in _ARTIFACT_SUFFIXES:
            continue
        state = read_state(path.stem)
        if state and pid_alive(state.get("pid", 0)):
            continue
        path.unlink(missing_ok=True)
        removed += 1
    return removed


# ── ssh config and exec framing ──────────────────────────────────
def ssh_config(host: str) -> dict:
    """Resolve HOST through ~/.ssh/config, empty when there is none."""
    path = Path.home() / ".ssh" / "config"
    if not path.is_file():
        return {}
    config = paramiko.SSHConfig()
    try:
        with path.open(encoding="utf-8") as fh:
            config.parse(fh)
        return dict(config.lookup(host))
    except OSError:
        return {}


STATE_COMMANDS = {
    "zsh": "{ typeset -gx; alias -L; functions; } 2>/dev/null",
    "bash": "{ declare -px; alias -p; declare -f; } 2>/dev/null",
}


def pty_payload(command: str, nonce: str, state_cmd: str | None = None) -> str:
    """One compound command whose markers bracket only the command's output.

    Prompts, PS2, echoed input and pre/post-command hooks all print outside the
    markers, so the captured slice is the command output alone.
    """
    parts = [
        f"{{ printf '\\036APTY{nonce}B\\036'\n",
        f"{command}\n",
        "__apty_rc=$?\n",
        f"printf '\\036APTY{nonce}E%s\\036' \"$__apty_rc\"\n",
        f"printf '\\036APTY{nonce}C%s\\036' \"$PWD\"\n",
    ]
    if state_cmd:
        parts += [
            f"printf '\\036APTY{nonce}S\\036'\n",
            f"{state_cmd} | base64 | tr -d '\\n'\n",
            f"printf '\\036APTY{nonce}s\\036'\n",
        ]
    parts.append("}\n")
    return "".join(parts)


def parse_exec(buf: str, nonce: str) -> tuple[str, int] | None:
    """Output and exit code between the markers, or None if not finished."""
    begin = _MARK_B.format(n=nonce)
    start = buf.rfind(begin)
    if start < 0:
        return None
    end = re.search(re.escape(_MARK_E.format(n=nonce)) + r"(\d+)\x1e", buf[start:])
    if not end:
        return None
    return buf[start + len(begin) : start + end.start()], int(end.group(1))


def parse_cwd(buf: str, nonce: str) -> str | None:
    """The shell's working directory reported after a command."""
    match = re.search(rf"\x1eAPTY{nonce}C(.*?)\x1e", buf, re.S)
    return match.group(1) if match else None


def parse_state(buf: str, nonce: str) -> str | None:
    """Decode the base64 shell state snapshot emitted after a command."""
    begin = f"\x1eAPTY{nonce}S\x1e"
    start = buf.rfind(begin)
    if start < 0:
        return None
    end = buf.find(f"\x1eAPTY{nonce}s\x1e", start)
    if end < 0:
        return None
    blob = buf[start + len(begin) : end].strip()
    try:
        return base64.b64decode(blob, validate=True).decode("utf-8", errors="replace")
    except ValueError:
        return None


_STATE_DROP = re.compile(
    r"^(?:declare -[A-Za-z]*x[A-Za-z]* |typeset -[A-Za-z]*x[A-Za-z]* )?"
    r"(?:SSH_AUTH_SOCK|SSH_CONNECTION|SSH_CLIENT|SSH_TTY|SSH_AGENT_PID)="
)


def filter_state(text: str) -> str:
    """Keep replayable shell state, dropping per-connection SSH variables."""
    lines = [line for line in text.splitlines() if not _STATE_DROP.match(line)]
    return "\n".join(lines) + ("\n" if lines else "")


def parse_partial(buf: str, nonce: str) -> str:
    """Whatever the command printed before an interrupted exec."""
    begin = _MARK_B.format(n=nonce)
    start = buf.rfind(begin)
    if start < 0:
        return ""
    body = buf[start + len(begin) :]
    for stop in ("\x03", "^C"):
        index = body.find(stop)
        if index >= 0:
            return body[:index]
    return body


def clean_output(text: str) -> str:
    return text.replace("\r\n", "\n").replace("\r", "\n")


_ANSI = re.compile(
    r"\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)"  # OSC sequences
    r"|\x1b\[[0-9;?]*[ -/]*[@-~]"  # CSI sequences
    r"|\x1b[@-Z\\-_]"  # other escapes
)
_CONTROL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")


_MARK_TEXT = re.compile(r"\\036APTY[0-9a-f]{8}(?:B|Z|E[0-9]*)\\036|APTY[0-9a-f]{8}(?:B|Z|E[0-9]*)")


def strip_ansi(text: str) -> str:
    """Drop terminal escapes, control bytes and agent-pty framing markers."""
    return _MARK_TEXT.sub("", _CONTROL.sub("", _ANSI.sub("", text)))


# ── forwarding spec ──────────────────────────────────────────────
def split_spec(spec: str) -> list[str]:
    """Split on colons outside [brackets], so IPv6 literals stay whole."""
    parts: list[str] = []
    current = ""
    depth = 0
    for char in spec:
        if char == "[":
            depth += 1
        elif char == "]":
            depth = max(0, depth - 1)
        if char == ":" and depth == 0:
            parts.append(current)
            current = ""
        else:
            current += char
    parts.append(current)
    return parts


def strip_brackets(host: str) -> str:
    return host[1:-1] if host.startswith("[") and host.endswith("]") else host


def format_hostport(host: str, port: int) -> str:
    return f"[{host}]:{port}" if ":" in host else f"{host}:{port}"


def parse_forward(spec: str) -> tuple[str, int, str, int]:
    """Parse [bind:]port:host:port into (bind, listen_port, host, target_port)."""
    parts = split_spec(spec)
    try:
        if len(parts) == 3:
            bind, listen_port, host, target_port = "127.0.0.1", int(parts[0]), parts[1], int(parts[2])
        elif len(parts) == 4:
            bind, listen_port, host, target_port = parts[0] or "127.0.0.1", int(parts[1]), parts[2], int(parts[3])
        else:
            raise ValueError
    except ValueError as exc:
        raise ValueError(f"bad forward spec: {spec}") from exc
    if not 0 <= listen_port <= 65535 or not 1 <= target_port <= 65535:
        raise ValueError(f"bad forward port: {spec}")
    return strip_brackets(bind), listen_port, strip_brackets(host), target_port


def parse_dynamic(spec: str) -> tuple[str, int]:
    """Parse [bind:]port for a SOCKS5 listener."""
    parts = split_spec(spec)
    if len(parts) == 1:
        bind, port = "127.0.0.1", parts[0]
    elif len(parts) == 2:
        bind, port = parts[0] or "127.0.0.1", parts[1]
    else:
        raise ValueError(f"bad dynamic spec: {spec}")
    try:
        listen_port = int(port)
    except ValueError as exc:
        raise ValueError(f"bad dynamic spec: {spec}") from exc
    if not 0 <= listen_port <= 65535:
        raise ValueError(f"bad dynamic port: {spec}")
    return strip_brackets(bind), listen_port


def parse_jump(spec: str) -> tuple[str | None, str, int | None]:
    """Parse [user@][host][:port] for a jump host."""
    user = None
    if "@" in spec:
        user, spec = spec.split("@", 1)
    parts = split_spec(spec)
    try:
        if len(parts) == 1:
            host, port = parts[0], None
        elif len(parts) == 2:
            host, port = parts[0], int(parts[1])
        else:
            raise ValueError
    except ValueError as exc:
        raise ValueError(f"bad jump spec: {spec}") from exc
    host = strip_brackets(host)
    if not host:
        raise ValueError(f"bad jump spec: {spec}")
    if port is not None and not 0 < port <= 65535:
        raise ValueError(f"bad jump port: {spec}")
    return user, host, port


def listen_socket(bind: str, port: int) -> socket.socket:
    """Bind a TCP listener, choosing IPv6 when the address contains a colon."""
    family = socket.AF_INET6 if ":" in bind else socket.AF_INET
    listener = socket.socket(family, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    if family == socket.AF_INET6:
        with contextlib.suppress(OSError):
            listener.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
    listener.bind((bind, port))
    listener.listen(16)
    return listener


def _pump(left, right) -> None:
    """Shuttle bytes both ways until either side closes."""
    try:
        while True:
            ready, _, _ = select.select([left, right], [], [], 1.0)
            if left in ready:
                data = left.recv(65536)
                if not data:
                    break
                right.sendall(data)
            if right in ready:
                data = right.recv(65536)
                if not data:
                    break
                left.sendall(data)
    except OSError:
        pass
    finally:
        for channel in (left, right):
            with contextlib.suppress(Exception):
                channel.close()


def _read_exact(conn: socket.socket, count: int) -> bytes:
    chunks = bytearray()
    while len(chunks) < count:
        chunk = conn.recv(count - len(chunks))
        if not chunk:
            raise OSError("connection closed")
        chunks.extend(chunk)
    return bytes(chunks)


def socks_handshake(conn: socket.socket) -> tuple[str, int]:
    """Server side of a SOCKS5 greeting and CONNECT request."""
    version, count = _read_exact(conn, 2)
    if version != 5:
        raise OSError("not socks5")
    if 0 not in _read_exact(conn, count):
        conn.sendall(b"\x05\xff")
        raise OSError("no acceptable auth")
    conn.sendall(b"\x05\x00")
    version, command, _reserved, address_type = _read_exact(conn, 4)
    if version != 5 or command != 1:
        conn.sendall(b"\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00")
        raise OSError("only CONNECT is supported")
    if address_type == 1:
        host = socket.inet_ntoa(_read_exact(conn, 4))
    elif address_type == 3:
        host = _read_exact(conn, _read_exact(conn, 1)[0]).decode("idna")
    elif address_type == 4:
        host = socket.inet_ntop(socket.AF_INET6, _read_exact(conn, 16))
    else:
        conn.sendall(b"\x05\x08\x00\x01\x00\x00\x00\x00\x00\x00")
        raise OSError("bad address type")
    port = int.from_bytes(_read_exact(conn, 2), "big")
    return host, port


# ── file transfer helpers ────────────────────────────────────────
def remote_path(sftp: paramiko.SFTPClient, path: str) -> str:
    """Expand a leading ~ against the remote home, which sftp does not do."""
    if path == "~" or path.startswith("~/"):
        home = sftp.normalize(".")
        return posixpath.join(home, path[2:]) if len(path) > 2 else home
    return path


def _mkdirs(sftp: paramiko.SFTPClient, path: str) -> None:
    """Create a remote directory and its parents, ignoring existing ones."""
    path = path.rstrip("/")
    if not path or path == "/":
        return
    try:
        sftp.stat(path)
        return
    except OSError:
        pass
    _mkdirs(sftp, posixpath.dirname(path))
    with contextlib.suppress(OSError):
        sftp.mkdir(path)


def _remote_is_dir(sftp: paramiko.SFTPClient, path: str) -> bool:
    try:
        return stat.S_ISDIR(sftp.stat(path).st_mode)
    except OSError:
        return False


def _put_tree(sftp: paramiko.SFTPClient, local: str, remote: str) -> int:
    if os.path.islink(local):
        if os.path.isdir(local):
            return 0  # skip symlinked directories, which can loop
        sftp.put(local, remote)
        return 1
    if os.path.isdir(local):
        with contextlib.suppress(OSError):
            sftp.mkdir(remote)
        total = 0
        for name in sorted(os.listdir(local)):
            total += _put_tree(sftp, os.path.join(local, name), posixpath.join(remote, name))
        return total
    sftp.put(local, remote)
    return 1


def _get_tree(sftp: paramiko.SFTPClient, remote: str, local: str) -> int:
    if stat.S_ISDIR(sftp.lstat(remote).st_mode):
        os.makedirs(local, exist_ok=True)
        total = 0
        for entry in sftp.listdir_attr(remote):
            total += _get_tree(sftp, posixpath.join(remote, entry.filename), os.path.join(local, entry.filename))
        return total
    os.makedirs(os.path.dirname(os.path.abspath(local)), exist_ok=True)
    sftp.get(remote, local)
    return 1


# ── daemon ───────────────────────────────────────────────────────
class SessionServer:
    """Owns one SSH connection with an interactive PTY shell."""

    def __init__(self, config: dict) -> None:
        self.id: str = config["id"]
        self.name: str = config.get("name") or self.id
        self.host: str = config["host"]
        self.port: int | None = config.get("port")
        self.user: str | None = config.get("user")
        self.password: str | None = config.get("password")
        self.key_file: str | None = config.get("key_file")
        self.insecure: bool = bool(config.get("insecure"))
        self.agent: bool = config.get("agent", True) is not False
        self.connect_timeout: int = int(config.get("connect_timeout") or 20)
        self.keepalive: int = int(config.get("keepalive", 30))
        self.forward_agent: bool = bool(config.get("forward_agent"))
        self.jump: list[str] = list(config.get("jump") or [])
        self.jump_passwords: list[str] = list(config.get("jump_passwords") or [])
        self.reconnect_attempts: int = int(config.get("reconnect") or 0)
        self.ttl_seconds: int = int(config["ttl"]) * 60
        self._target_host: str = self.host
        self._connected = False
        self._reconnecting = False
        self._cwd: str | None = None
        self._shell: str | None = None
        self._shell_state: str = ""
        self._jump_clients: list[paramiko.SSHClient] = []
        self.started_at = datetime.now(UTC)

        self._cond = threading.Condition()
        self._exec_lock = threading.Lock()
        self._close_lock = threading.Lock()
        self._stop = threading.Event()
        self._buf = bytearray()
        self._attached: socket.socket | None = None
        self._last_activity = time.time()
        self._client: paramiko.SSHClient | None = None
        self._chan: paramiko.Channel | None = None
        self._transcript = None
        self._interrupt = threading.Event()
        self._forwards: list[dict] = []
        self._forward_seq = 0

    # -- lifecycle
    def start(self) -> None:
        ensure_dirs()
        self._resolve_target()
        self._connect()
        self._write_state()
        audit(self.id, "connect", host=self.host, user=self.user, port=self.port, name=self.name)
        threading.Thread(target=self._reader, name="pty-reader", daemon=True).start()
        threading.Thread(target=self._ttl_guard, name="ttl", daemon=True).start()

    def _resolve_target(self) -> None:
        settings = ssh_config(self.host)
        self._target_host = str(settings.get("hostname") or self.host)
        self.user = self.user or settings.get("user") or os.environ.get("USER") or "root"
        self.port = self.port or int(settings.get("port") or 22)
        if not self.key_file and not self.password:
            keys = settings.get("identityfile") or []
            if keys:
                self.key_file = os.path.expanduser(keys[0])

    def _jump_specs(self) -> list[str]:
        if self.jump:
            return self.jump
        proxy = str(ssh_config(self.host).get("proxyjump") or "")
        if proxy and proxy.lower() != "none":
            return [part.strip() for part in proxy.split(",") if part.strip()]
        return []

    def _connect_target(self) -> paramiko.SSHClient:
        resolved = []
        for index, spec in enumerate(self._jump_specs()):
            jump_user, jump_host, jump_port = parse_jump(spec)
            settings = ssh_config(jump_host)
            password = self.jump_passwords[index] if index < len(self.jump_passwords) else None
            jump_key = None
            if not password:
                keys = settings.get("identityfile") or []
                if keys:
                    jump_key = os.path.expanduser(keys[0])
            resolved.append(
                (
                    str(settings.get("hostname") or jump_host),
                    jump_user or settings.get("user") or self.user,
                    jump_port or int(settings.get("port") or 22),
                    jump_key,
                )
            )

        sock = None
        self._jump_clients = []
        for index, (hostname, user, port, key) in enumerate(resolved):
            if index + 1 < len(resolved):
                next_host, next_port = resolved[index + 1][0], resolved[index + 1][2]
            else:
                next_host, next_port = self._target_host, self.port
            client = self._build_client()
            client.connect(
                hostname=hostname,
                port=port,
                username=user,
                password=self.jump_passwords[index] if index < len(self.jump_passwords) else None,
                key_filename=key,
                sock=sock,
                timeout=self.connect_timeout,
                allow_agent=self.agent,
                look_for_keys=False,
            )
            transport = client.get_transport()
            if transport is None:
                raise RuntimeError(f"jump transport unavailable: {hostname}")
            transport.set_keepalive(self.keepalive)
            if not self.insecure:
                self._save_hosts(client)
            self._jump_clients.append(client)
            sock = transport.open_channel(
                "direct-tcpip", (next_host, next_port), ("127.0.0.1", 0), timeout=self.connect_timeout
            )

        client = self._build_client()
        client.connect(
            hostname=self._target_host,
            port=self.port,
            username=self.user,
            password=self.password,
            key_filename=self.key_file,
            sock=sock,
            timeout=self.connect_timeout,
            allow_agent=self.agent,
            look_for_keys=False,
        )
        return client

    def _save_hosts(self, client: paramiko.SSHClient) -> None:
        with contextlib.suppress(OSError):
            client.save_host_keys(str(KNOWN_HOSTS))
            os.chmod(KNOWN_HOSTS, 0o600)

    def _connect(self) -> None:
        client = self._connect_target()
        self._client = client
        if not self.insecure:
            self._save_hosts(client)
        transport = client.get_transport()
        if transport is None:
            raise RuntimeError("SSH transport unavailable")
        transport.set_keepalive(self.keepalive)
        if self.reconnect_attempts:
            self._shell = self._detect_shell(transport)
        cols, rows = _terminal_size()
        channel = transport.open_session()
        channel.get_pty(term=os.environ.get("TERM", "xterm-256color"), width=cols, height=rows)
        self._chan = channel
        if self.forward_agent:
            # The request must precede the shell, so sshd exports SSH_AUTH_SOCK.
            self._request_agent_forwarding()
        channel.invoke_shell()
        if self._transcript is None:
            self._transcript = transcript_path(self.id).open("ab")  # noqa: SIM115 - lives with the daemon
            os.chmod(transcript_path(self.id), 0o600)
        with self._cond:
            self._connected = True

    def _detect_shell(self, transport: paramiko.Transport) -> str | None:
        """Name of the login shell, when it is one whose state can be replayed."""
        try:
            chan = transport.open_session()
            chan.settimeout(5)
            chan.exec_command('basename "${SHELL:-sh}"')
            data = bytearray()
            while True:
                chunk = chan.recv(4096)
                if not chunk:
                    break
                data.extend(chunk)
            chan.close()
        except (OSError, paramiko.SSHException):
            return None
        name = data.decode("utf-8", errors="replace").strip()
        return name if name in STATE_COMMANDS else None

    def _request_agent_forwarding(self) -> None:
        if not os.environ.get("SSH_AUTH_SOCK"):
            raise RuntimeError("--forward-agent needs SSH_AUTH_SOCK")
        if self._chan is None:
            return
        self._chan.request_forward_agent(self._agent_handler)

    def _agent_handler(self, channel) -> None:
        path = os.environ.get("SSH_AUTH_SOCK")
        if not path:
            channel.close()
            return

        def proxy() -> None:
            try:
                sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                sock.settimeout(10)
                sock.connect(path)
                sock.settimeout(None)
            except OSError:
                channel.close()
                return
            _pump(channel, sock)

        threading.Thread(target=proxy, daemon=True).start()

    def _ready(self) -> tuple[bool, str]:
        if self._client is None or self._stop.is_set():
            return False, "session is closed"
        if not self._connected:
            return False, "session is reconnecting"
        return True, ""

    def _restore(self) -> None:
        chan = self._chan
        if chan is None:
            return
        if self._shell_state:
            self._restore_state()
        if self._cwd:
            chan.sendall(f"cd {shlex.quote(self._cwd)}\n")
        previous = [(entry["id"], entry["direction"], entry["spec"]) for entry in self._forwards]
        audit(self.id, "restore", cwd=self._cwd, forwards=len(previous))
        for entry in self._forwards:
            self._close_forward(entry)
        self._forwards.clear()
        for forward_id, direction, spec in previous:
            result = self.add_forward(direction, spec, forward_id=forward_id)
            if not result.get("ok"):
                audit(self.id, "restore_forward_failed", direction=direction, spec=spec, error=result.get("error"))

    def _restore_state(self) -> None:
        """Write the captured shell state to the remote and source it."""
        if self._client is None or self._chan is None or not self._shell_state:
            return
        sftp = self._client.open_sftp()
        try:
            home = sftp.normalize(".")
            path = posixpath.join(home, f".agent-pty-restore-{self.id}.sh")
            with sftp.file(path, "w") as handle:
                handle.write(self._shell_state)
            sftp.chmod(path, 0o600)
        finally:
            sftp.close()
        self._chan.sendall(f". {shlex.quote(path)}; rm -f {shlex.quote(path)}\n")
        audit(self.id, "restore_state", bytes=len(self._shell_state))

    def _on_disconnect(self) -> None:
        if self._stop.is_set():
            return
        with self._cond:
            self._connected = False
            self._chan = None
            start_loop = bool(self.reconnect_attempts) and not self._reconnecting
            if start_loop:
                self._reconnecting = True
        audit(self.id, "disconnect")
        if not self.reconnect_attempts:
            self.shutdown()
            return
        if start_loop:
            threading.Thread(target=self._reconnect_loop, name="reconnect", daemon=True).start()

    def _reconnect_loop(self) -> None:
        delay = 1.0
        for attempt in range(1, self.reconnect_attempts + 1):
            if self._stop.wait(delay):
                break
            self._touch()
            try:
                self._connect()
            except Exception as exc:  # noqa: BLE001 - any connect failure retries
                audit(self.id, "reconnect_failed", attempt=attempt, error=str(exc))
                delay = min(delay * 2, 30)
                continue
            audit(self.id, "reconnect", attempt=attempt)
            with self._cond:
                self._reconnecting = False
            try:
                self._restore()
            except Exception as exc:  # noqa: BLE001 - a failed restore must not stop the session
                audit(self.id, "restore_failed", error=str(exc))
            threading.Thread(target=self._reader, name="pty-reader", daemon=True).start()
            return
        with self._cond:
            self._reconnecting = False
        self.shutdown()

    def _build_client(self) -> paramiko.SSHClient:
        client = paramiko.SSHClient()
        if not self.insecure:
            with contextlib.suppress(OSError):
                client.load_system_host_keys()
            if KNOWN_HOSTS.exists():
                with contextlib.suppress(OSError):
                    client.load_host_keys(str(KNOWN_HOSTS))
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())  # noqa: S507 - TOFU, stored in KNOWN_HOSTS
        return client

    def serve(self) -> None:
        server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        server.bind(str(sock_path(self.id)))
        os.chmod(sock_path(self.id), 0o600)
        server.listen(16)
        server.settimeout(0.5)
        try:
            while not self._stop.is_set():
                try:
                    conn, _ = server.accept()
                except TimeoutError:
                    continue
                threading.Thread(target=self._handle, args=(conn,), daemon=True).start()
        finally:
            server.close()
            self.shutdown()

    def shutdown(self) -> None:
        if not self._close_lock.acquire(blocking=False):
            return
        self._stop.set()
        for entry in self._forwards:
            if entry.get("stop") is not None:
                entry["stop"].set()
            with contextlib.suppress(Exception):
                entry["closer"]()
        self._forwards.clear()
        for closer in (self._chan, self._client, self._transcript, *self._jump_clients):
            if closer is not None:
                with contextlib.suppress(Exception):
                    closer.close()
        self._chan = None
        self._client = None
        self._transcript = None
        self._jump_clients = []
        self._connected = False
        audit(self.id, "close")
        sock_path(self.id).unlink(missing_ok=True)
        state_path(self.id).unlink(missing_ok=True)

    def _write_state(self) -> None:
        state = {
            "id": self.id,
            "name": self.name,
            "host": self.host,
            "port": self.port,
            "user": self.user,
            "pid": os.getpid(),
            "socket": str(sock_path(self.id)),
            "started_at": datetime.now(UTC).isoformat(timespec="seconds"),
            "ttl": self.ttl_seconds // 60,
            "transcript": str(transcript_path(self.id)),
        }
        tmp = state_path(self.id).with_suffix(".tmp")
        tmp.write_text(json.dumps(state), encoding="utf-8")
        os.chmod(tmp, 0o600)
        tmp.replace(state_path(self.id))

    def _touch(self) -> None:
        with self._cond:
            self._last_activity = time.time()

    def _ttl_guard(self) -> None:
        while not self._stop.wait(5):
            with self._cond:
                idle = time.time() - self._last_activity
            if idle > self.ttl_seconds:
                audit(self.id, "idle_timeout", idle_seconds=int(idle))
                self.shutdown()
                return

    # -- pty pump
    def _reader(self) -> None:
        chan = self._chan
        if chan is None:
            return
        while not self._stop.is_set():
            try:
                ready = chan.recv_ready()
            except (OSError, EOFError):
                break
            if not ready:
                try:
                    select.select([chan], [], [], 0.2)
                except (OSError, ValueError):
                    break
                if chan.closed:
                    break
                continue
            try:
                data = chan.recv(65536)
            except (OSError, EOFError):
                break
            if not data:
                break
            with self._cond:
                self._buf.extend(data)
                if len(self._buf) > BUFFER_LIMIT:
                    del self._buf[: len(self._buf) - BUFFER_LIMIT]
                attached = self._attached
                self._cond.notify_all()
            if self._transcript is not None:
                with contextlib.suppress(OSError):
                    self._transcript.write(data)
                    self._transcript.flush()
            if attached is not None:
                try:
                    attached.sendall(data)
                except OSError:
                    self._detach()
        self._on_disconnect()

    def _detach(self) -> None:
        with self._cond:
            self._attached = None

    # -- operations
    def exec(self, command: str, timeout: float = 120) -> dict:
        """Run one command inside the live PTY shell, keeping its state."""
        ready, error = self._ready()
        chan = self._chan
        if not ready or chan is None:
            return {"ok": False, "error": error or "session is reconnecting"}
        if not self._exec_lock.acquire(blocking=False):
            return {"ok": False, "error": "session is attached to a terminal"}
        nonce = uuid.uuid4().hex[:8]
        self._interrupt.clear()
        try:
            with self._cond:
                if self._attached is not None:
                    return {"ok": False, "error": "session is attached to a terminal"}
                self._buf.clear()
            # Quiet the line discipline first so the typed payload is never echoed.
            chan.sendall(f"stty -echo; printf '\\036APTY{nonce}Z\\036'\n".encode())
            quiet_deadline = time.time() + 3
            while time.time() < quiet_deadline:
                if f"\x1eAPTY{nonce}Z\x1e" in self._buffer_text():
                    break
                time.sleep(0.02)
            with self._cond:
                self._buf.clear()
            chan.sendall(pty_payload(command, nonce, STATE_COMMANDS.get(self._shell) if self._shell else None))
            deadline = time.time() + timeout
            while time.time() < deadline and not self._stop.is_set() and self._chan is chan:
                self._touch()
                with self._cond:
                    parsed = parse_exec(self._buf.decode("utf-8", errors="replace"), nonce)
                    if parsed is None and not self._interrupt.is_set():
                        self._cond.wait(0.05)
                if parsed is not None:
                    output, code = parsed
                    buffer = self._buffer_text()
                    cwd = parse_cwd(buffer, nonce)
                    if cwd:
                        self._cwd = cwd
                    if self._shell:
                        snapshot = parse_state(buffer, nonce)
                        if snapshot is None:
                            deadline = time.time() + 2
                            while time.time() < deadline:
                                snapshot = parse_state(self._buffer_text(), nonce)
                                if snapshot is not None:
                                    break
                                with self._cond:
                                    self._cond.wait(0.02)
                        if snapshot:
                            self._shell_state = filter_state(snapshot)[:1_048_576] or self._shell_state
                    audit(self.id, "exec", command=command[:200], exit_code=code)
                    return {"ok": True, "output": clean_output(output), "exit_code": code}
                if self._interrupt.is_set():
                    break
            if self._chan is not chan:
                partial = clean_output(parse_partial(self._buffer_text(), nonce))
                audit(self.id, "exec", command=command[:200], exit_code=255, connection_lost=True)
                return {
                    "ok": False,
                    "error": "connection lost, session is reconnecting",
                    "output": partial,
                    "exit_code": 255,
                }
            interrupted = self._interrupt.is_set()
            if not interrupted:
                with contextlib.suppress(Exception):
                    chan.sendall(b"\x03")
            for _ in range(10):
                parsed = parse_exec(self._buffer_text(), nonce)
                if parsed is not None:
                    break
                with self._cond:
                    self._cond.wait(0.05)
            partial = clean_output(parse_partial(self._buffer_text(), nonce))
            code = 130 if interrupted else 124
            audit(self.id, "exec", command=command[:200], exit_code=code, interrupted=interrupted)
            return {
                "ok": False,
                "error": "interrupted" if interrupted else f"command timed out after {timeout}s",
                "output": partial,
                "exit_code": code,
                "interrupted": interrupted,
                "timed_out": not interrupted,
            }
        finally:
            with contextlib.suppress(Exception):
                chan.sendall(b"stty echo\n")
            self._exec_lock.release()

    def _buffer_text(self) -> str:
        with self._cond:
            return self._buf.decode("utf-8", errors="replace")

    def write(self, data: str) -> dict:
        """Send raw input to the PTY shell."""
        ready, error = self._ready()
        chan = self._chan
        if not ready or chan is None:
            return {"ok": False, "error": error or "session is reconnecting"}
        if not self._exec_lock.acquire(blocking=False):
            return {"ok": False, "error": "session is busy"}
        try:
            chan.sendall(data.encode())
            self._touch()
            audit(self.id, "write", bytes=len(data))
            return {"ok": True}
        except (OSError, paramiko.SSHException) as exc:
            return {"ok": False, "error": str(exc)}
        finally:
            self._exec_lock.release()

    def interrupt(self) -> dict:
        chan = self._chan
        if chan is None:
            return {"ok": False, "error": "session is reconnecting" if self.reconnect_attempts else "session is closed"}
        self._interrupt.set()
        try:
            chan.sendall(b"\x03")
        except (OSError, paramiko.SSHException) as exc:
            return {"ok": False, "error": str(exc)}
        self._touch()
        audit(self.id, "interrupt")
        return {"ok": True}

    def rename(self, name: str) -> dict:
        self.name = name
        self._write_state()
        audit(self.id, "rename", name=name)
        return {"ok": True, "name": name}

    def resize(self, cols: int, rows: int) -> dict:
        if self._chan is None:
            return {"ok": False, "error": "session is closed"}
        try:
            self._chan.resize_pty(width=cols, height=rows)
        except (OSError, paramiko.SSHException) as exc:
            return {"ok": False, "error": str(exc)}
        return {"ok": True}

    # -- forwarding
    def add_forward(self, direction: str, spec: str, forward_id: int | None = None) -> dict:
        ready, error = self._ready()
        if not ready:
            return {"ok": False, "error": error}
        try:
            if direction == "dynamic":
                bind, listen_port = parse_dynamic(spec)
                host, target_port = "socks5", 0
            else:
                bind, listen_port, host, target_port = parse_forward(spec)
        except ValueError as exc:
            return {"ok": False, "error": str(exc)}

        if direction in ("local", "dynamic"):
            try:
                listener = listen_socket(bind, listen_port)
            except OSError as exc:
                return {"ok": False, "error": str(exc)}
            listen_port = listener.getsockname()[1]
            stop = threading.Event()
            accepter = self._accept_local if direction == "local" else self._accept_socks
            thread = threading.Thread(target=accepter, args=(listener, host, target_port, stop), daemon=True)
            thread.start()
            closer = listener.close
        elif direction == "remote":
            transport = self._client.get_transport()
            if transport is None:
                return {"ok": False, "error": "connection lost"}

            def handler(chan, _origin, _server, host=host, port=target_port):
                threading.Thread(target=self._remote_conn, args=(chan, host, port), daemon=True).start()

            try:
                transport.request_port_forward(bind, listen_port, handler)
            except (OSError, paramiko.SSHException) as exc:
                return {"ok": False, "error": str(exc)}
            closer = lambda: transport.cancel_port_forward(bind, listen_port)  # noqa: E731
            stop, thread = None, None
        else:
            return {"ok": False, "error": f"unknown direction: {direction}"}

        if forward_id is None:
            with self._cond:
                self._forward_seq += 1
                forward_id = self._forward_seq
        entry = {
            "id": forward_id,
            "direction": direction,
            "spec": spec,
            "listen": format_hostport(bind, listen_port),
            "target": "socks5" if direction == "dynamic" else format_hostport(host, target_port),
            "closer": closer,
            "stop": stop,
            "thread": thread,
        }
        self._forwards.append(entry)
        audit(self.id, "forward", direction=direction, listen=entry["listen"], target=entry["target"])
        return {"ok": True, **{k: entry[k] for k in ("id", "direction", "listen", "target")}}

    def _close_forward(self, entry: dict) -> None:
        stop = entry.get("stop")
        if stop is not None:
            stop.set()
        with contextlib.suppress(Exception):
            entry["closer"]()
        thread = entry.get("thread")
        if thread is not None:
            thread.join(1.5)

    def _accept_local(self, listener: socket.socket, host: str, port: int, stop: threading.Event) -> None:
        listener.settimeout(0.5)
        while not self._stop.is_set() and not stop.is_set():
            try:
                conn, _ = listener.accept()
            except TimeoutError:
                continue
            except OSError:
                return
            threading.Thread(target=self._local_conn, args=(conn, host, port), daemon=True).start()

    def _local_conn(self, conn: socket.socket, host: str, port: int) -> None:
        transport = self._client.get_transport() if self._client else None
        if transport is None:
            conn.close()
            return
        try:
            peer = conn.getpeername()
            channel = transport.open_channel("direct-tcpip", (host, port), peer, timeout=10)
        except (OSError, paramiko.SSHException):
            conn.close()
            return
        _pump(conn, channel)

    def _accept_socks(self, listener: socket.socket, _host: str, _port: int, stop: threading.Event) -> None:
        listener.settimeout(0.5)
        while not self._stop.is_set() and not stop.is_set():
            try:
                conn, _ = listener.accept()
            except TimeoutError:
                continue
            except OSError:
                return
            threading.Thread(target=self._socks_conn, args=(conn,), daemon=True).start()

    def _socks_conn(self, conn: socket.socket) -> None:
        try:
            conn.settimeout(15)
            host, port = socks_handshake(conn)
            transport = self._client.get_transport() if self._client else None
            if transport is None:
                return
            try:
                channel = transport.open_channel("direct-tcpip", (host, port), conn.getpeername(), timeout=10)
            except (OSError, paramiko.SSHException):
                conn.sendall(b"\x05\x05\x00\x01\x00\x00\x00\x00\x00\x00")
                conn.close()
                return
            conn.sendall(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")
            conn.settimeout(None)
            self._touch()
        except (OSError, paramiko.SSHException, UnicodeError):
            with contextlib.suppress(OSError):
                conn.close()
            return
        _pump(conn, channel)

    def _remote_conn(self, channel, host: str, port: int) -> None:
        try:
            conn = socket.create_connection((host, port), timeout=10)
        except OSError:
            channel.close()
            return
        _pump(channel, conn)

    def remove_forward(self, forward_id: int) -> dict:
        for entry in list(self._forwards):
            if entry["id"] == forward_id:
                self._close_forward(entry)
                self._forwards.remove(entry)
                audit(self.id, "unforward", id=forward_id)
                return {"ok": True}
        return {"ok": False, "error": f"no forward {forward_id}"}

    def forwards(self) -> list[dict]:
        return [{k: entry[k] for k in ("id", "direction", "listen", "target")} for entry in self._forwards]

    # -- file transfer
    def upload(self, local: str, remote: str | None, directory: bool) -> dict:
        ready, error = self._ready()
        if not ready:
            return {"ok": False, "error": error}
        sftp = self._sftp()
        if sftp is None:
            return {"ok": False, "error": "sftp unavailable"}
        try:
            source = os.path.abspath(local)
            if not os.path.exists(source):
                return {"ok": False, "error": f"no such path: {local}"}
            target = remote_path(sftp, remote) if remote else posixpath.basename(source.rstrip(os.sep))
            if directory or os.path.isdir(source):
                _mkdirs(sftp, posixpath.dirname(target))
                files = _put_tree(sftp, source, target)
            else:
                if target.endswith("/") or _remote_is_dir(sftp, target):
                    target = posixpath.join(target, posixpath.basename(source))
                _mkdirs(sftp, posixpath.dirname(target))
                sftp.put(source, target)
                files = 1
            audit(self.id, "upload", local=source, remote=target, files=files)
            return {"ok": True, "remote": target, "files": files}
        except (OSError, paramiko.SSHException) as exc:
            return {"ok": False, "error": str(exc)}
        finally:
            sftp.close()

    def download(self, remote: str, local: str | None, directory: bool) -> dict:
        ready, error = self._ready()
        if not ready:
            return {"ok": False, "error": error}
        sftp = self._sftp()
        if sftp is None:
            return {"ok": False, "error": "sftp unavailable"}
        try:
            remote = remote_path(sftp, remote)
            target = local or posixpath.basename(remote.rstrip("/"))
            if directory or _remote_is_dir(sftp, remote):
                files = _get_tree(sftp, remote, target)
            else:
                if target.endswith(("/", os.sep)):
                    os.makedirs(target, exist_ok=True)
                if os.path.isdir(target):
                    target = os.path.join(target, posixpath.basename(remote))
                os.makedirs(os.path.dirname(os.path.abspath(target)), exist_ok=True)
                sftp.get(remote, target)
                files = 1
            audit(self.id, "download", remote=remote, local=os.path.abspath(target), files=files)
            return {"ok": True, "local": os.path.abspath(target), "files": files}
        except (OSError, paramiko.SSHException) as exc:
            return {"ok": False, "error": str(exc)}
        finally:
            sftp.close()

    def info(self) -> dict:
        with self._cond:
            idle = int(time.time() - self._last_activity)
            attached = self._attached is not None
        return {
            "ok": True,
            "id": self.id,
            "name": self.name,
            "host": self.host,
            "port": self.port,
            "user": self.user,
            "idle_seconds": idle,
            "ttl": self.ttl_seconds // 60,
            "started_at": self.started_at.isoformat(timespec="seconds"),
            "uptime_seconds": int((datetime.now(UTC) - self.started_at).total_seconds()),
            "attached": attached,
            "connected": self._connected,
            "reconnect": self.reconnect_attempts,
            "jumps": self._jump_specs(),
            "forward_agent": self.forward_agent,
            "shell": self._shell,
            "state_bytes": len(self._shell_state),
            "running": self._exec_lock.locked(),
            "transcript": str(transcript_path(self.id)),
            "forwards": self.forwards(),
        }

    def _sftp(self) -> paramiko.SFTPClient | None:
        if self._client is None:
            return None
        try:
            return self._client.open_sftp()
        except paramiko.SSHException:
            return None

    # -- protocol
    def _handle(self, conn: socket.socket) -> None:
        try:
            line = _recv_line(conn)
            if not line:
                return
            request = json.loads(line)
            op = request.get("op")
            args = request.get("args") or {}
            if op == "attach":
                self._attach(conn, args)
                return
            if op == "exec":
                response = self.exec(args.get("command", ""), float(args.get("timeout", 120)))
            elif op == "write":
                response = self.write(args.get("data", ""))
            elif op == "interrupt":
                response = self.interrupt()
            elif op == "rename":
                response = self.rename(args.get("name", ""))
            elif op == "resize":
                response = self.resize(int(args.get("cols", 0)), int(args.get("rows", 0)))
            elif op == "forward":
                response = self.add_forward(args.get("direction", "local"), args.get("spec", ""))
            elif op == "unforward":
                response = self.remove_forward(int(args.get("id", 0)))
            elif op == "upload":
                response = self.upload(args["local"], args.get("remote"), bool(args.get("dir")))
            elif op == "download":
                response = self.download(args["remote"], args.get("local"), bool(args.get("dir")))
            elif op == "info":
                response = self.info()
            elif op == "close":
                conn.sendall(b'{"ok": true}\n')
                self.shutdown()
                return
            else:
                response = {"ok": False, "error": f"unknown op: {op}"}
            conn.sendall(json.dumps(response).encode() + b"\n")
        except (OSError, ValueError, KeyError) as exc:
            with contextlib.suppress(OSError):
                conn.sendall(json.dumps({"ok": False, "error": str(exc)}).encode() + b"\n")
        finally:
            with contextlib.suppress(Exception):
                conn.close()

    def _attach(self, conn: socket.socket, args: dict) -> None:
        chan = self._chan
        if chan is None:
            conn.sendall(b'{"ok": false, "error": "session is closed"}\n')
            return
        if not self._exec_lock.acquire(blocking=False):
            conn.sendall(b'{"ok": false, "error": "session is busy running a command"}\n')
            with contextlib.suppress(Exception):
                conn.close()
            return
        try:
            with self._cond:
                self._attached = conn
            conn.sendall(b'{"ok": true}\n')
            cols = int(args.get("cols") or 0)
            rows = int(args.get("rows") or 0)
            if rows and cols:
                chan.resize_pty(width=cols, height=rows)
            self._touch()
            while not self._stop.is_set():
                data = conn.recv(65536)
                if not data:
                    break
                if b"\x1d" in data:  # Ctrl-] detaches
                    data = data.split(b"\x1d", 1)[0]
                    if data:
                        chan.sendall(data)
                    break
                chan.sendall(data)
                self._touch()
        except OSError:
            pass
        finally:
            self._detach()
            audit(self.id, "detach")
            self._exec_lock.release()
            with contextlib.suppress(Exception):
                conn.close()


# ── daemon entry point ───────────────────────────────────────────
def _terminal_size() -> tuple[int, int]:
    try:
        size = os.get_terminal_size()
        return size.columns, size.lines
    except OSError:
        return 120, 40


def _recv_line(conn: socket.socket, limit: int = 1_048_576) -> str:
    chunks = bytearray()
    while len(chunks) < limit:
        chunk = conn.recv(4096)
        if not chunk:
            break
        chunks.extend(chunk)
        if b"\n" in chunk:
            break
    return bytes(chunks).split(b"\n", 1)[0].decode("utf-8", errors="replace")


def serve(config_path: str) -> None:
    """Read a session config, drop it, then own the session until closed."""
    path = Path(config_path)
    config = json.loads(path.read_text(encoding="utf-8"))
    path.unlink(missing_ok=True)
    server = SessionServer(config)
    try:
        server.start()
    except Exception as exc:  # noqa: BLE001 - daemon boundary, report then exit
        audit(config.get("id", "unknown"), "connect_failed", error=str(exc))
        print(f"agent-pty daemon: {exc}", file=sys.stderr, flush=True)
        sys.exit(1)
    server.serve()


if __name__ == "__main__":
    serve(sys.argv[1])
