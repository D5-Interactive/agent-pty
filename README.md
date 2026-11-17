# agent-pty

Persistent SSH sessions with a full interactive PTY, held open in the background.

Open a session once. Then run commands, attach to the live shell, or move files
from separate terminal invocations. Commands share one shell, so `cd`, exports
and functions persist between them. The session survives until you close it or
its idle TTL expires.

## Install

```bash
uv tool install --from . agent-pty   # local checkout
uv sync && uv run agent-pty --help   # development
```

## Quick start

```bash
# 1. open a background session (password, key, or interactive prompt)
agent-pty connect d5dog -u deploy --key-file ~/.ssh/id_ed25519 --name web --ttl 30

# 2. use it from anywhere
agent-pty exec -s web 'cd /srv/app && git pull'
agent-pty exec -s web 'pwd'                   # /srv/app, state kept
agent-pty shell  -s web                       # full PTY, Ctrl-] detaches
agent-pty logs   -s web -n 50                 # PTY transcript
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
| `sessions` | List live sessions: id, name, target, pid, start, TTL. |
| `info` | Show one session: host, user, idle, TTL, attached, running, transcript path. |
| `exec CMD...` | Run a command inside the live PTY shell. State persists across calls. |
| `shell` | Attach to the live PTY. `Ctrl-]` detaches without closing the session. |
| `logs` | Print the session transcript, with `-f` to follow it. |
| `upload FILE [REMOTE]` | Upload one file. A trailing `/` on REMOTE means that directory. |
| `upload-dir DIR [REMOTE]` | Upload a directory tree. |
| `download FILE [LOCAL]` | Download one file. A trailing `/` on LOCAL means that directory. |
| `download-dir DIR [LOCAL]` | Download a directory tree. |
| `close` | Close a session and its SSH connection. `--all` closes every session. |

## Flags

| Flag | Commands | Meaning |
| --- | --- | --- |
| `-p, --port` | `connect` | SSH port, default 22. |
| `-u, --user` | `connect` | Remote user, defaults to `$USER`. |
| `-i, --key-file` | `connect` | Private key file. Any key type paramiko supports. |
| `--password` | `connect` | SSH password. Prompted when neither password nor key is given. |
| `--ttl` | `connect` | Idle timeout in minutes, default 30. |
| `-n, --name` | `connect` | Friendly session name, usable with `-s`. |
| `--insecure` | `connect` | Do not verify or record host keys. |
| `-s, --session` | all but `connect`, `sessions` | Session id, name, or unique id prefix. |
| `--timeout` | `exec` | Seconds to wait, default 120. On expiry the command is interrupted and agent-pty exits 124. |
| `-n, --lines` | `logs` | Lines to print, default 40. |
| `-f, --follow` | `logs` | Keep printing new output until Ctrl-C. |
| `--raw` | `logs` | Keep terminal escape sequences. |
| `--json` | `sessions`, `info` | Machine-readable output. |
| `--all` | `close` | Close every live session. |
| `-h, --help` | anywhere | Full help, including every subcommand and flag. |

## Behavior

- One daemon process per session, under `~/.agent-pty/sessions/` (mode 0700).
  The daemon dies with its session.
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
  session id, action, command, exit code, transfer paths. Passwords are never
  written there.
- Remote `~` is expanded for `upload` and `download` targets.

## Layout

```
src/agent_pty/main.py      CLI and client transport
src/agent_pty/session.py   SSH session, PTY pump, exec framing, transfer, daemon
tests/test_cli.py          help surface, exec framing, transcript cleaning
```

## Development

```bash
uv sync --all-groups
uv run ruff check . && uv run ruff format --check .
uv run pytest -q
```
