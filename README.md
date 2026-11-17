# agent-pty

Persistent SSH sessions with a full interactive PTY, held open in the background.

Open a session once. Then run commands, attach to the live shell, or move files
from separate terminal invocations. The session survives command exit until you
close it or its idle TTL expires.

## Install

```bash
uv tool install --from . agent-pty   # local checkout
uv sync && uv run agent-pty --help   # development
```

## Quick start

```bash
# 1. open a background session (password, key, or interactive prompt)
agent-pty connect d5dog -u deploy --key-file ~/.ssh/id_ed25519 --ttl 30

# 2. use it from anywhere
agent-pty exec -s d5dog-deploy-1a2b3c 'systemctl --user status app'
agent-pty shell  -s d5dog-deploy-1a2b3c      # full PTY, Ctrl-] detaches
agent-pty upload ./build.tar.gz '~/releases/'
agent-pty sessions
agent-pty close  -s d5dog-deploy-1a2b3c
```

`-s` is optional when exactly one session is live.

## Commands

| Command | Purpose |
| --- | --- |
| `connect HOST` | Open a background session with an interactive PTY. |
| `sessions` | List live sessions with target, PID, start time, TTL. |
| `info` | Show one session: host, user, idle seconds, TTL, attached state. |
| `exec CMD...` | Run a command on the session connection. Prints stdout and stderr, exits with the remote exit code. |
| `shell` | Attach to the live PTY. `Ctrl-]` detaches without closing the session. |
| `upload FILE [REMOTE]` | Upload one file. A trailing `/` on REMOTE means that directory. |
| `upload-dir DIR [REMOTE]` | Upload a directory tree. |
| `download FILE [LOCAL]` | Download one file. |
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
| `-s, --session` | all but `connect`, `sessions` | Session id or unique prefix. |
| `--timeout` | `exec` | Seconds to wait for the command, default 120. |
| `--all` | `close` | Close every live session. |
| `-h, --help` | anywhere | Full help, including every subcommand and flag. |

## Behavior

- Sessions live in a per-user daemon, one process per session, under
  `~/.agent-pty/sessions/` (mode 0700). The daemon dies with its session.
- `exec` runs over the session's SSH connection, so stdout, stderr, and the
  remote exit code stay clean. It does not disturb the interactive shell.
- The interactive shell is a real PTY (`invoke_shell`) and survives detach.
- Remote `~` is expanded for `upload` and `download` targets.
- Idle TTL closes the session and removes its socket and state files.
- Every operation is appended to `~/.agent-pty/audit.jsonl`: timestamp,
  session id, action, command, exit code, transfer paths. Passwords are never
  written to the audit log.

## Layout

```
src/agent_pty/main.py      CLI and client transport
src/agent_pty/session.py   SSH session, PTY pump, file transfer, daemon
tests/test_cli.py          help surface and session id checks
```

## Development

```bash
uv sync --all-groups
uv run ruff check . && uv run ruff format --check .
uv run pytest -q
```
