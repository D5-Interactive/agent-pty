# agent-pty

Persistent SSH sessions with a full interactive PTY, held open in the background.

Open a session once. Then run commands, attach to the live shell, forward ports,
or move files from separate terminal invocations. Commands share one shell, so
`cd`, exports and functions persist between them. The session survives until you
close it or its idle TTL expires.

## Install

```bash
uv tool install --from . agent-pty   # local checkout
uv sync && uv run agent-pty --help   # development
```

Python 3.11 or newer.

## Quick start

```bash
# 1. open a background session. HOST resolves through ~/.ssh/config
agent-pty connect web --name web --ttl 30

# 2. use it from anywhere
agent-pty exec -s web 'cd /srv/app && git pull'
agent-pty exec -s web 'pwd'                   # /srv/app, state kept
agent-pty shell  -s web                       # full PTY, Ctrl-] detaches
agent-pty logs   -s web -n 50                 # PTY transcript
agent-pty forward -s web -L 8080:localhost:80 # local tunnel to the remote port
agent-pty forward -s web -D 1080              # SOCKS5 proxy through the session
agent-pty connect web -J bastion             # reach web through a jump host
agent-pty upload ./build.tar.gz '~/releases/'
agent-pty sessions
agent-pty close  -s web
```

`-s` accepts a session id, its name, or a unique id prefix. It can be omitted
when exactly one session is live.

## Commands

| Command | Purpose |
| --- | --- |
| `connect HOST` | Open a background session with an interactive PTY. |
| `sessions` | List live sessions: id, name, target, pid, idle, start, TTL. |
| `info` | Show one session: host, user, idle, TTL, attached, running, forwards, transcript. |
| `exec CMD...` | Run a command inside the live PTY shell. State persists across calls. |
| `shell` | Attach to the live PTY. `Ctrl-]` detaches without closing the session. |
| `send TEXT` | Type text into the live PTY shell. |
| `interrupt` | Send Ctrl-C, and stop a running `exec` with exit code 130. |
| `logs` | Print the session transcript, with `-f` to follow it. |
| `rename NEWNAME` | Give the session a new name. |
| `forward` | Add, list, or remove SSH port forwards, including a SOCKS5 proxy. |
| `upload FILE [REMOTE]` | Upload one file. A trailing `/` on REMOTE means that directory. |
| `upload-dir DIR [REMOTE]` | Upload a directory tree. |
| `download FILE [LOCAL]` | Download one file. A trailing `/` on LOCAL means that directory. |
| `download-dir DIR [LOCAL]` | Download a directory tree. |
| `close` | Close a session and its SSH connection. `--all` closes every session. |
| `prune` | Delete files left by closed or crashed sessions. |

## Flags

| Flag | Commands | Meaning |
| --- | --- | --- |
| `-p, --port` | `connect` | SSH port. Default 22 or `~/.ssh/config`. |
| `-u, --user` | `connect` | Remote user. Default from `~/.ssh/config`, `$USER`, or `root`. |
| `-i, --key-file` | `connect` | Private key file. Default from `~/.ssh/config` IdentityFile. |
| `--password` | `connect` | SSH password. Prompted when neither password nor key is given. |
| `--ttl` | `connect` | Idle timeout in minutes, default 30. |
| `-n, --name` | `connect` | Friendly session name, usable with `-s`. |
| `--insecure` | `connect` | Do not verify or record host keys. |
| `--agent / --no-agent` | `connect` | Use ssh-agent keys, on by default. |
| `-J, --jump` | `connect` | `[USER@]HOST[:PORT]`, repeatable for a chain. |
| `--jump-password` | `connect` | Password for jump hosts; they otherwise use ssh config keys or the agent. |
| `--forward-agent` | `connect` | Forward the local ssh-agent to the remote side. |
| `--reconnect` | `connect` | Reconnect attempts after a dropped connection, default 0. |
| `--connect-timeout` | `connect` | SSH connect timeout in seconds, default 20. |
| `--keepalive` | `connect` | SSH keepalive interval in seconds, default 30, 0 disables. |
| `-s, --session` | most commands | Session id, name, or unique id prefix. |
| `--timeout` | `exec` | Seconds to wait, default 120. On expiry the command is interrupted and agent-pty exits 124. |
| `--no-newline` | `send` | Type the text without a trailing newline. |
| `-n, --lines` | `logs` | Lines to print, default 40. |
| `-f, --follow` | `logs` | Keep printing new output until Ctrl-C. |
| `--raw` | `logs` | Keep terminal escape sequences. |
| `-L, --local` | `forward` | `[BIND:]PORT:HOST:PORT`, listen locally. Repeatable. |
| `-R, --remote` | `forward` | `[BIND:]PORT:HOST:PORT`, listen on the remote side. Repeatable. |
| `-D, --dynamic` | `forward` | `[BIND:]PORT`, listen locally as a SOCKS5 proxy. Repeatable. |
| `--list` | `forward` | Show active forwards. |
| `--remove ID` | `forward` | Remove a forward by id. |
| `--json` | `sessions`, `info` | Machine-readable output. |
| `--all` | `close` | Close every live session. |
| `-h, --help` | anywhere | Full help, including every subcommand and flag. |

## Port forwarding

```bash
agent-pty forward -s web -L 8080:localhost:80      # local 8080 -> web's port 80
agent-pty forward -s web -L 15432:db:5432          # local 15432 -> web -> db:5432
agent-pty forward -s web -R 9000:localhost:3000    # web's 9000 -> your 3000
agent-pty forward -s web -D 1080                   # SOCKS5, resolves from the remote side
agent-pty forward -s web --list
agent-pty forward -s web --remove 1
```

For `-L` and `-D`, `HOST:PORT` is resolved on the remote side. For `-R`, it is
resolved on your side. All default to binding `127.0.0.1`. IPv6 literals use
brackets, for example `-L [::1]:8080:localhost:80`.

```bash
curl --socks5-hostname 127.0.0.1:1080 http://internal.service/
```

## Behavior

- One daemon process per session, under `~/.agent-pty/sessions/` (mode 0700).
  The daemon dies with its session.
- `HOST` resolves through `~/.ssh/config` for HostName, User, Port and the first
  IdentityFile.
- `exec` sends one compound command to the interactive shell and brackets it
  with control-byte markers, so prompts, echoed input and shell hooks stay out
  of the captured output. Since a PTY merges streams, stderr appears with
  stdout. The remote exit code becomes agent-pty's exit code.
- `exec` and `shell` are mutually exclusive on one session: attaching while a
  command runs is refused, and vice versa.
- `shell` is a real PTY. Window size is applied on attach and followed on every
  resize.
- Host keys use trust on first use: keys come from `~/.ssh/known_hosts` and
  `~/.agent-pty/known_hosts`. A changed key fails the connection; remove the
  stale entry there after a legitimate rotation. `--insecure` skips this.
- The full PTY stream is appended to `~/.agent-pty/sessions/<id>.out` and read
  by `logs`.
- Every operation is appended to `~/.agent-pty/audit.jsonl`: timestamp,
  session id, action, command, exit code, transfer paths, forwards. Passwords
  are never written there.
- Jump hosts are honoured from `-J`, or from `ProxyJump` in `~/.ssh/config`.
  Chains of any length work, and each hop uses its own ssh config or SSH agent.
- `--forward-agent` requests agent forwarding before the shell starts, so the
  remote shell gets `SSH_AUTH_SOCK`. It needs `SSH_AUTH_SOCK` locally.
- `--reconnect N` retries a dropped connection with backoff. A reconnected
  session restores the last known working directory and re-creates its port
  forwards. Shell environment, aliases and functions are not restored.
- The idle TTL closes abandoned sessions and their forwards.
- Remote `~` is expanded for `upload` and `download` targets.
- `upload` creates missing remote parent directories and copies directories
  without needing `upload-dir`. Symlinked directories are skipped to avoid loops.
- `download` detects a remote directory and copies the tree without needing
  `download-dir`.
- `sessions --json` adds live fields: idle, uptime, attached, running and
  forwards. `logs -f` stops when the session ends.
- `exec` framing expects a POSIX shell (bash, zsh or sh).

## Layout

```
src/agent_pty/main.py      CLI and client transport
src/agent_pty/session.py   SSH session, PTY pump, exec framing, forwarding, daemon
tests/test_cli.py          help surface, exec framing, forwards, transcript cleaning
```

## Development

```bash
uv sync --all-groups
uv run ruff check . && uv run ruff format --check .
uv run pytest -q
```
