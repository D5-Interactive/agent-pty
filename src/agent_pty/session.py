"""Persistent SSH PTY sessions and the local daemon that owns them."""

from __future__ import annotations

import contextlib
import json
import os
import posixpath
import re
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
    except OSError, ValueError:
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


# ── exec framing ─────────────────────────────────────────────────
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


def strip_ansi(text: str) -> str:
    """Drop terminal escapes and control bytes, keeping newlines and tabs."""
    return _CONTROL.sub("", _ANSI.sub("", text))


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
        self.port: int = int(config["port"])
        self.user: str = config["user"]
        self.password: str | None = config.get("password")
        self.key_file: str | None = config.get("key_file")
        self.insecure: bool = bool(config.get("insecure"))
        self.ttl_seconds: int = int(config["ttl"]) * 60

        self._lock = threading.Lock()
        self._exec_lock = threading.Lock()
        self._close_lock = threading.Lock()
        self._stop = threading.Event()
        self._buf = bytearray()
        self._attached: socket.socket | None = None
        self._last_activity = time.time()
        self._client: paramiko.SSHClient | None = None
        self._chan: paramiko.Channel | None = None
        self._transcript = None

    # -- lifecycle
    def start(self) -> None:
        ensure_dirs()
        self._client = self._build_client()
        self._client.connect(
            hostname=self.host,
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
        with self._lock:
            self._last_activity = time.time()

    def _ttl_guard(self) -> None:
        while not self._stop.wait(5):
            with self._lock:
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
            if chan.recv_ready():
                data = chan.recv(65536)
                if not data:
                    break
                with self._lock:
                    self._buf.extend(data)
                    if len(self._buf) > BUFFER_LIMIT:
                        del self._buf[: len(self._buf) - BUFFER_LIMIT]
                    attached = self._attached
                if self._transcript is not None:
                    with contextlib.suppress(OSError):
                        self._transcript.write(data)
                        self._transcript.flush()
                if attached is not None:
                    try:
                        attached.sendall(data)
                    except OSError:
                        self._detach()
            elif chan.closed:
                break
            else:
                time.sleep(0.02)
        self._stop.set()

    def _detach(self) -> None:
        with self._lock:
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
        try:
            with self._lock:
                if self._attached is not None:
                    return {"ok": False, "error": "session is attached to a terminal"}
                self._buf.clear()
            chan.sendall(pty_payload(command, nonce))
            deadline = time.time() + timeout
            while time.time() < deadline and not self._stop.is_set():
                self._touch()
                parsed = parse_exec(self._buffer_text(), nonce)
                if parsed is not None:
                    output, code = parsed
                    audit(self.id, "exec", command=command[:200], exit_code=code)
                    return {"ok": True, "output": clean_output(output), "exit_code": code}
                time.sleep(0.03)
            with contextlib.suppress(Exception):
                chan.sendall(b"\x03")
            for _ in range(40):
                parsed = parse_exec(self._buffer_text(), nonce)
                if parsed is not None:
                    break
                time.sleep(0.05)
            partial = clean_output(parse_partial(self._buffer_text(), nonce))
            audit(self.id, "exec", command=command[:200], exit_code=124, timed_out=True)
            return {
                "ok": False,
                "error": f"command timed out after {timeout}s",
                "output": partial,
                "exit_code": 124,
                "timed_out": True,
            }
        finally:
            self._exec_lock.release()

    def _buffer_text(self) -> str:
        with self._lock:
            return self._buf.decode("utf-8", errors="replace")

    def resize(self, cols: int, rows: int) -> dict:
        if self._chan is None:
            return {"ok": False, "error": "session is closed"}
        self._chan.resize_pty(width=cols, height=rows)
        return {"ok": True}

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
        with self._lock:
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
            elif op == "upload":
                response = self.upload(args["local"], args.get("remote"), bool(args.get("dir")))
            elif op == "download":
                response = self.download(args["remote"], args.get("local"), bool(args.get("dir")))
            elif op == "resize":
                response = self.resize(int(args.get("cols", 0)), int(args.get("rows", 0)))
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
            with self._lock:
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
