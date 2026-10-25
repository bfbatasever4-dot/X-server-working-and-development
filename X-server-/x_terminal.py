"""Loopback-only PTY sessions for the authenticated X Server owner."""
from __future__ import annotations

import codecs
import fcntl
import os
import pty
import secrets
import signal
import struct
import subprocess
import termios
import threading
import time
from collections import deque


class TerminalSession:
    def __init__(self, session_id: str):
        self.id = session_id
        self._master_fd, slave_fd = pty.openpty()
        self._lock = threading.Lock()
        self._output = deque(maxlen=1000)
        self._closed = threading.Event()
        environment = os.environ.copy()
        environment.update({"TERM": "xterm-256color", "PS1": "", "PROMPT_COMMAND": ""})
        try:
            self.process = subprocess.Popen(
                ["bash", "--noprofile", "--norc", "-i"],
                stdin=slave_fd,
                stdout=slave_fd,
                stderr=slave_fd,
                cwd=os.getcwd(),
                env=environment,
                start_new_session=True,
                close_fds=True,
            )
        except BaseException:
            os.close(slave_fd)
            os.close(self._master_fd)
            raise
        os.close(slave_fd)
        self.resize(100, 30)
        self._reader = threading.Thread(target=self._read_output, daemon=True)
        self._reader.start()

    @property
    def running(self) -> bool:
        return self.process.poll() is None

    def _read_output(self):
        decoder = codecs.getincrementaldecoder("utf-8")("replace")
        try:
            while True:
                chunk = os.read(self._master_fd, 4096)
                if not chunk:
                    break
                text = decoder.decode(chunk)
                if text:
                    with self._lock:
                        self._output.append(text)
        except OSError:
            pass
        finally:
            tail = decoder.decode(b"", final=True)
            if tail:
                with self._lock:
                    self._output.append(tail)
            try:
                os.close(self._master_fd)
            except OSError:
                pass
            self._closed.set()

    def write(self, text: str):
        if not self.running:
            raise RuntimeError("Terminal process is not running")
        data = text.encode("utf-8")
        while data:
            written = os.write(self._master_fd, data)
            data = data[written:]

    def read_output(self) -> str:
        with self._lock:
            chunks = list(self._output)
            self._output.clear()
        return "".join(chunks)

    def resize(self, columns: int, rows: int):
        columns = max(20, min(int(columns), 300))
        rows = max(5, min(int(rows), 100))
        fcntl.ioctl(self._master_fd, termios.TIOCSWINSZ, struct.pack("HHHH", rows, columns, 0, 0))
        if self.running:
            os.killpg(self.process.pid, signal.SIGWINCH)

    def terminate(self):
        if self.running:
            try:
                os.killpg(self.process.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            try:
                self.process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(self.process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                self.process.wait(timeout=2)
        try:
            os.close(self._master_fd)
        except OSError:
            pass
        self._closed.set()


class TerminalManager:
    def __init__(self, max_sessions: int = 4):
        self.max_sessions = max_sessions
        self._sessions: dict[str, TerminalSession] = {}
        self._lock = threading.Lock()

    def start(self) -> TerminalSession:
        with self._lock:
            self._sessions = {key: value for key, value in self._sessions.items() if value.running}
            if len(self._sessions) >= self.max_sessions:
                raise RuntimeError("The terminal session limit has been reached")
            session_id = secrets.token_urlsafe(24)
            terminal = TerminalSession(session_id)
            self._sessions[session_id] = terminal
            return terminal

    def get(self, session_id: str) -> TerminalSession | None:
        with self._lock:
            return self._sessions.get(session_id)

    def terminate(self, session_id: str) -> bool:
        with self._lock:
            terminal = self._sessions.pop(session_id, None)
        if terminal:
            terminal.terminate()
            return True
        return False

    def terminate_all(self):
        with self._lock:
            sessions = list(self._sessions.values())
            self._sessions.clear()
        for terminal in sessions:
            terminal.terminate()