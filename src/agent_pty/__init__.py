"""agent-pty: SSH with persistent, background PTY sessions."""

from .main import main
from .session import list_sessions

__all__ = ["list_sessions", "main"]
__version__ = "0.2.0"
