"""Persistent SSH PTY sessions and the local daemon that owns them."""

from __future__ import annotations

import contextlib
import json
import os
import posixpath
import re
import select
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


def pty_payload(command: str, nonce: str) -> str:
    """One compound command whose markers bracket only the command's output.

    Prompts, PS2, echoed input and pre/post-command hooks all print outside the
    markers, so the captured slice is the command output alone.
    """
    return (
        f"{{ printf '\\036APTY{nonce}B\\036'\n"
        f"{command}\n"
        "__apty_rc=$?\n"
        f"printf '\\036APTY{nonce}E%s\\036' \"$__apty_rc\"\n"
        "}\n"
    )


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


_MARK_TEXT = re.compile(r"\\036APTY[0-9a-f]{8}[BZE]\\036|APTY[0-9a-f]{8}[BZE]")


def strip_ansi(text: str) -> str:
    """Drop terminal escapes, control bytes and agent-pty framing markers."""
    return _MARK_TEXT.sub("", _CONTROL.sub("", _ANSI.sub("", text)))


# ── forwarding spec ──────────────────────────────────────────────
def parse_forward(spec: str) -> tuple[str, int, str, int]:
    """Parse [bind:]port:host:port into (bind, listen_port, host, target_port)."""
    parts = spec.split(":")
    try:
        if len(parts) == 3:
            bind, listen_port, host, target_port = "127.0.0.1", int(parts[0]), parts[1], int(parts[2])
        elif len(parts) == 4:
            bind, listen_port, host, target_port = parts[0] or "127.0.0.1", int(parts[1]), parts[2], int(parts[3])
        else:
            raise ValueError
    except ValueError as exc:
        raise ValueError(f"bad forward spec: {spec}") from exc
    return bind, listen_port, host, target_port


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


# ── file transfer helpers ────────────────────────────────────────
def remote_path(sftp: paramiko.SFTPClient, path: str) -> str:
    """Expand a leading ~ against the remote home, which sftp does not do."""
    if path == "~" or path.startswith("~/"):
        home = sftp.normalize(".")
        return posixpath.join(home, path[2:]) if len(path) > 2 else home
    return path


def _put_tree(sftp: paramiko.SFTPClient, local: str, remote: str) -> int:
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
    if stat.S_ISDIR(sftp.stat(remote).st_mode):
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
        self.ttl_seconds: int = int(config["ttl"]) * 60

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
        settings = ssh_config(self.host)
        hostname = str(settings.get("hostname") or self.host)
        self.user = self.user or settings.get("user") or os.environ.get("USER") or "root"
        self.port = self.port or int(settings.get("port") or 22)
        if not self.key_file and not self.password:
            keys = settings.get("identityfile") or []
            if keys:
                self.key_file = os.path.expanduser(keys[0])

        self._client = self._build_client()
        self._client.connect(
            hostname=hostname,
            port=self.port,
            username=self.user,
            password=self.password,
            key_filename=self.key_file,
            timeout=20,
            allow_agent=False,
            look_for_keys=False,
        )
        if not self.insecure:
            with contextlib.suppress(OSError):
                self._client.save_host_keys(str(KNOWN_HOSTS))
                os.chmod(KNOWN_HOSTS, 0o600)

        transport = self._client.get_transport()
        if transport is None:
            raise RuntimeError("SSH transport unavailable")
        transport.set_keepalive(30)
        cols, rows = _terminal_size()
        channel = transport.open_session()
        channel.get_pty(term=os.environ.get("TERM", "xterm-256color"), width=cols, height=rows)
        channel.invoke_shell()
        self._chan = channel
        self._transcript = transcript_path(self.id).open("ab")  # noqa: SIM115 - lives with the daemon
        os.chmod(transcript_path(self.id), 0o600)

        self._write_state()
        audit(self.id, "connect", host=self.host, user=self.user, port=self.port, name=self.name)

        threading.Thread(target=self._reader, name="pty-reader", daemon=True).start()
        threading.Thread(target=self._ttl_guard, name="ttl", daemon=True).start()

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
            with contextlib.suppress(Exception):
                entry["closer"]()
        self._forwards.clear()
        for closer in (self._chan, self._client, self._transcript):
            if closer is not None:
                with contextlib.suppress(Exception):
                    closer.close()
        self._chan = None
        self._client = None
        self._transcript = None
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
        self._stop.set()

    def _detach(self) -> None:
        with self._cond:
            self._attached = None

    # -- operations
    def exec(self, command: str, timeout: float = 120) -> dict:
        """Run one command inside the live PTY shell, keeping its state."""
        chan = self._chan
        if chan is None or self._stop.is_set():
            return {"ok": False, "error": "session is closed"}
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
            chan.sendall(pty_payload(command, nonce))
            deadline = time.time() + timeout
            while time.time() < deadline and not self._stop.is_set():
                self._touch()
                with self._cond:
                    parsed = parse_exec(self._buf.decode("utf-8", errors="replace"), nonce)
                    if parsed is None and not self._interrupt.is_set():
                        self._cond.wait(0.05)
                if parsed is not None:
                    output, code = parsed
                    audit(self.id, "exec", command=command[:200], exit_code=code)
                    return {"ok": True, "output": clean_output(output), "exit_code": code}
                if self._interrupt.is_set():
                    break
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
        chan = self._chan
        if chan is None or self._stop.is_set():
            return {"ok": False, "error": "session is closed"}
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
            return {"ok": False, "error": "session is closed"}
        self._interrupt.set()
        chan.sendall(b"\x03")
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
        self._chan.resize_pty(width=cols, height=rows)
        return {"ok": True}

    # -- forwarding
    def add_forward(self, direction: str, spec: str) -> dict:
        if self._client is None or self._stop.is_set():
            return {"ok": False, "error": "session is closed"}
        try:
            bind, listen_port, host, target_port = parse_forward(spec)
        except ValueError as exc:
            return {"ok": False, "error": str(exc)}

        if direction == "local":
            listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                listener.bind((bind, listen_port))
                listener.listen(16)
            except OSError as exc:
                listener.close()
                return {"ok": False, "error": str(exc)}
            listen_port = listener.getsockname()[1]
            threading.Thread(target=self._accept_local, args=(listener, host, target_port), daemon=True).start()
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
        else:
            return {"ok": False, "error": f"unknown direction: {direction}"}

        with self._cond:
            self._forward_seq += 1
            forward_id = self._forward_seq
        entry = {
            "id": forward_id,
            "direction": direction,
            "listen": f"{bind}:{listen_port}",
            "target": f"{host}:{target_port}",
            "closer": closer,
        }
        self._forwards.append(entry)
        audit(self.id, "forward", direction=direction, listen=entry["listen"], target=entry["target"])
        return {"ok": True, **{k: entry[k] for k in ("id", "direction", "listen", "target")}}

    def _accept_local(self, listener: socket.socket, host: str, port: int) -> None:
        listener.settimeout(0.5)
        while not self._stop.is_set():
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
            channel = transport.open_channel("direct-tcpip", (host, port), peer)
        except (OSError, paramiko.SSHException):
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
                with contextlib.suppress(Exception):
                    entry["closer"]()
                self._forwards.remove(entry)
                audit(self.id, "unforward", id=forward_id)
                return {"ok": True}
        return {"ok": False, "error": f"no forward {forward_id}"}

    def forwards(self) -> list[dict]:
        return [{k: entry[k] for k in ("id", "direction", "listen", "target")} for entry in self._forwards]

    # -- file transfer
    def upload(self, local: str, remote: str | None, directory: bool) -> dict:
        sftp = self._sftp()
        if sftp is None:
            return {"ok": False, "error": "sftp unavailable"}
        try:
            source = os.path.abspath(local)
            if not os.path.exists(source):
                return {"ok": False, "error": f"no such path: {local}"}
            target = remote_path(sftp, remote) if remote else posixpath.basename(source.rstrip(os.sep))
            if directory:
                files = _put_tree(sftp, source, target)
            else:
                if target.endswith("/"):
                    target = posixpath.join(target, posixpath.basename(source))
                sftp.put(source, target)
                files = 1
            audit(self.id, "upload", local=source, remote=target, files=files)
            return {"ok": True, "remote": target, "files": files}
        except (OSError, paramiko.SSHException) as exc:
            return {"ok": False, "error": str(exc)}
        finally:
            sftp.close()

    def download(self, remote: str, local: str | None, directory: bool) -> dict:
        sftp = self._sftp()
        if sftp is None:
            return {"ok": False, "error": "sftp unavailable"}
        try:
            remote = remote_path(sftp, remote)
            target = local or posixpath.basename(remote.rstrip("/"))
            if directory:
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
            "attached": attached,
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
