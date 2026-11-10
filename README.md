SSH into machines with full interactive pty — background session management.

Connect via SSH and run a command with an interactive PTY. Sessions stay open in the background; idle TTL triggers timeout exit. Every action is audited to JSON for traceability.

## Usage

```bash
agent-pty ssh-connect [OPTIONS]
```

### Options

| Option | Description |
|--------|-------------|
| `--host` | Remote host to connect to (required) |
| `--port` | SSH port, default 22 |
| `--user` | Remote username |
| `--key-file` | Path to SSH private key file |
| `--password` | Password for authentication |
| `--command` | Command or command string to execute on remote machine (required) |
| `--session` | User already having a session open in background |
| `--cmd` | CLI command to run on remote machine, overrides --command |
| `--run-file` | Path to local file to transfer to remote via sftp/scp |
| `-f, --get-file` | Download single file from remote to local via sftp |
| `-d, --get-dir` | Copy directory from remote to local via sftp |
| `--close` | Close the connection and session |
| `--ttl` | Idle timeout in minutes for sessions (default 30) |

## Audit

Every action is recorded as a JSON audit event with timestamp, action, host, user, command, output lines, stderr lines.
