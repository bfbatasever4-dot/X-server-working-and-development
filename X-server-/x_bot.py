"""Bounded project-inspection and approved-tool executor for X Bot."""
from __future__ import annotations

import difflib
import hashlib
import json
import os
import re
import shutil
import subprocess
import tempfile
import time
import uuid
from pathlib import Path


class XBot:
    MAX_FILE_BYTES = 1_000_000
    EXCLUDED_DIRS = {".git", "__pycache__", "data", "logs", ".venv", "venv", "node_modules"}
    EXCLUDED_NAMES = {".env", ".env.local", "session_secret", "id_rsa", "id_ed25519"}
    APPROVED_COMMANDS = {
        "test": ["python", "-m", "unittest", "discover", "-s", "tests", "-v"],
        "compile": ["python", "-m", "py_compile", "x_server.py", "x_terminal.py", "x_bot.py"],
        "git_status": ["git", "status", "--short"],
        "git_diff": ["git", "diff", "--"],
    }

    def __init__(self, project_root: Path, backup_root: Path, config_path: Path | None = None):
        self.project_root = project_root.resolve()
        self.backup_root = backup_root.resolve()
        self.backup_root.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.config_path = config_path or self.project_root / "x_bot_config.json"
        self.enabled_commands = set(self.APPROVED_COMMANDS)
        try:
            configuration = json.loads(self.config_path.read_text(encoding="utf-8"))
            configured_commands = configuration.get("enabled_commands", [])
            if isinstance(configured_commands, list):
                self.enabled_commands.intersection_update(
                    name for name in configured_commands if isinstance(name, str)
                )
        except (OSError, ValueError, AttributeError):
            self.enabled_commands.clear()
        self.pending: dict[str, dict] = {}
        self.backups: dict[str, Path] = {}
        self.rollback_targets: dict[str, dict] = {}

    def resolve_project_path(self, value: str) -> Path:
        if not isinstance(value, str) or not value or "\x00" in value:
            raise ValueError("Choose a project-relative path")
        path = (self.project_root / value).resolve()
        try:
            relative = path.relative_to(self.project_root)
        except ValueError as exc:
            raise ValueError("Path is outside the project") from exc
        if any(part in self.EXCLUDED_DIRS for part in relative.parts):
            raise ValueError("This project path is not available to X Bot")
        if (path.name in self.EXCLUDED_NAMES or path.name.startswith(".env")
            or path.suffix.lower() in {".pem", ".key", ".p12", ".pfx", ".db", ".sqlite", ".sqlite3"}):
            raise ValueError("This sensitive project file is not available to X Bot")
        return path

    def list_files(self, limit: int = 300) -> list[str]:
        files = []
        for path in self.project_root.rglob("*"):
            relative = path.relative_to(self.project_root)
            if any(part in self.EXCLUDED_DIRS for part in relative.parts):
                continue
            if (path.name in self.EXCLUDED_NAMES or path.name.startswith(".env")
                    or path.suffix.lower() in {".pem", ".key", ".p12", ".pfx", ".db", ".sqlite", ".sqlite3"}):
                continue
            try:
                if path.is_file() and not path.is_symlink():
                    files.append(relative.as_posix())
            except OSError:
                continue
            if len(files) >= limit:
                break
        return sorted(files)

    def read_file(self, value: str) -> str:
        path = self.resolve_project_path(value)
        if not path.is_file() or path.is_symlink():
            raise ValueError("Project file not found")
        if path.stat().st_size > self.MAX_FILE_BYTES:
            raise ValueError("File exceeds the 1 MB inspection limit")
        return path.read_text(encoding="utf-8")

    def run_approved(self, name: str) -> dict:
        command = self.APPROVED_COMMANDS.get(name) if name in self.enabled_commands else None
        if not command:
            raise ValueError("Command is not on X Bot's approved list")
        started = time.monotonic()
        safe_environment = {
            key: value for key, value in os.environ.items()
            if not re.search(r"(?i)(api.?key|token|password|secret|credential|private.?key)", key)
        }
        result = subprocess.run(
            command,
            cwd=self.project_root,
            capture_output=True,
            text=True,
            timeout=90 if name == "test" else 30,
            check=False,
            env=safe_environment,
        )
        output = redact_secrets((result.stdout + result.stderr)[-12000:])
        return {
            "command": " ".join(command),
            "returncode": result.returncode,
            "output": output,
            "duration_seconds": round(time.monotonic() - started, 2),
        }

    def prepare_change(self, value: str, content: str, user_id: int) -> dict:
        path = self.resolve_project_path(value)
        if path.is_symlink() or not path.is_file():
            raise ValueError("Only existing regular project files can be changed")
        if path.stat().st_size > self.MAX_FILE_BYTES or len(content.encode("utf-8")) > self.MAX_FILE_BYTES:
            raise ValueError("Current and proposed files must be at most 1 MB")
        original = path.read_text(encoding="utf-8")
        change_id = uuid.uuid4().hex
        diff = "".join(difflib.unified_diff(
            original.splitlines(keepends=True), content.splitlines(keepends=True),
            fromfile=value, tofile=value + " (proposed)",
        ))
        self.pending[change_id] = {
            "path": path,
            "content": content,
            "user_id": user_id,
            "original_hash": hashlib.sha256(original.encode("utf-8")).hexdigest(),
        }
        return {"id": change_id, "path": value, "diff": diff[:20000]}

    def approve_change(self, change_id: str, user_id: int) -> dict:
        change = self.pending.pop(change_id, None)
        if not change or change["user_id"] != user_id:
            raise ValueError("Change proposal expired or belongs to another session")
        path = change["path"]
        current_hash = hashlib.sha256(path.read_bytes()).hexdigest()
        if current_hash != change["original_hash"]:
            raise ValueError("The file changed after preview; prepare a new proposal before approval")
        backup_name = f"{time.strftime('%Y%m%dT%H%M%SZ', time.gmtime())}-{uuid.uuid4().hex[:8]}-{path.name}.bak"
        backup_path = self.backup_root / backup_name
        shutil.copy2(path, backup_path)
        backup_path.chmod(0o600)
        self.backups[change_id] = backup_path
        self.rollback_targets[change_id] = {
            "path": path,
            "user_id": user_id,
            "applied_hash": hashlib.sha256(change["content"].encode("utf-8")).hexdigest(),
        }
        temporary = None
        try:
            with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=path.parent, delete=False) as handle:
                temporary = Path(handle.name)
                handle.write(change["content"])
                handle.flush()
                os.fsync(handle.fileno())
            temporary.chmod(path.stat().st_mode & 0o777)
            temporary.replace(path)
        except BaseException:
            if temporary:
                temporary.unlink(missing_ok=True)
            raise
        return {"path": path.relative_to(self.project_root).as_posix(), "backup": backup_name}

    def rollback(self, change_id: str, user_id: int) -> str:
        backup_path = self.backups.get(change_id)
        target = self.rollback_targets.get(change_id)
        if not backup_path or not backup_path.is_file():
            raise ValueError("No available backup exists for this change")
        if not target:
            raise ValueError("Rollback target is unavailable after restart")
        if target["user_id"] != user_id:
            raise ValueError("Rollback is not authorized")
        path = target["path"]
        current_hash = hashlib.sha256(path.read_bytes()).hexdigest()
        if current_hash != target["applied_hash"]:
            raise ValueError("The file changed after X Bot applied it; refusing to overwrite newer work")
        shutil.copy2(backup_path, path)
        self.rollback_targets.pop(change_id, None)
        return path.relative_to(self.project_root).as_posix()


def redact_secrets(text: str) -> str:
    text = re.sub(
        r"(?i)(api[_-]?key|access[_-]?token|refresh[_-]?token|password|secret|credential)(\s*[:=]\s*)([^\s,;&]+)",
        r"\1\2[REDACTED]",
        text,
    )
    for name, value in os.environ.items():
        if re.search(r"(?i)(key|token|password|secret|credential)", name) and len(value) >= 8:
            text = text.replace(value, "[REDACTED]")
    return text
