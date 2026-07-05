"""Race-safe file upload helper for issue #85.

The vulnerable pattern is a check-then-write upload path: two concurrent
requests can validate the same target and then overwrite or interleave data.
This module keeps validation and publish under a per-target lock, writes to a
temporary file in the destination directory, and publishes with an atomic
replace only after the full payload is verified.
"""

from __future__ import annotations

import os
import re
import tempfile
import threading
from pathlib import Path
from typing import Iterable


SAFE_FILENAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")


class UnsafeUpload(ValueError):
    """Raised when upload input is unsafe or violates policy."""


class UploadConflict(FileExistsError):
    """Raised when an upload would overwrite an existing file."""


class AtomicUploadStore:
    """Store uploaded bytes without check/write race windows."""

    def __init__(
        self,
        upload_dir: str | os.PathLike[str],
        *,
        max_bytes: int = 10 * 1024 * 1024,
        allowed_extensions: Iterable[str] | None = None,
    ) -> None:
        self.upload_dir = Path(upload_dir).resolve()
        self.upload_dir.mkdir(parents=True, exist_ok=True)
        if max_bytes <= 0:
            raise ValueError("max_bytes must be positive")
        self.max_bytes = max_bytes
        self.allowed_extensions = self._normalize_extensions(allowed_extensions)
        self._locks: dict[Path, threading.Lock] = {}
        self._locks_guard = threading.Lock()

    @staticmethod
    def _normalize_extensions(extensions: Iterable[str] | None) -> frozenset[str] | None:
        if extensions is None:
            return None
        normalized = frozenset(
            item.lower() if item.startswith(".") else f".{item.lower()}"
            for item in extensions
        )
        if not normalized:
            raise ValueError("allowed_extensions cannot be empty")
        return normalized

    def _target_lock(self, path: Path) -> threading.Lock:
        with self._locks_guard:
            lock = self._locks.get(path)
            if lock is None:
                lock = threading.Lock()
                self._locks[path] = lock
            return lock

    def _safe_target(self, filename: str) -> Path:
        if not isinstance(filename, str):
            raise UnsafeUpload("filename must be text")
        if "\x00" in filename or "/" in filename or "\\" in filename:
            raise UnsafeUpload("filename must not contain path separators")
        if filename in {"", ".", ".."} or not SAFE_FILENAME_RE.fullmatch(filename):
            raise UnsafeUpload("filename contains unsupported characters")

        target = (self.upload_dir / filename).resolve()
        try:
            target.relative_to(self.upload_dir)
        except ValueError as exc:
            raise UnsafeUpload("filename escapes upload directory") from exc

        if self.allowed_extensions is not None and target.suffix.lower() not in self.allowed_extensions:
            raise UnsafeUpload("file extension is not allowed")
        return target

    def save(self, filename: str, content: bytes, *, overwrite: bool = False) -> Path:
        """Validate and atomically save one upload.

        The existence check, temporary write, validation, and final publish are
        protected by a per-target lock. With ``overwrite=False`` concurrent
        attempts for the same target produce exactly one winner.
        """

        if not isinstance(content, bytes):
            raise UnsafeUpload("content must be bytes")
        if len(content) == 0:
            raise UnsafeUpload("empty uploads are not accepted")
        if len(content) > self.max_bytes:
            raise UnsafeUpload("upload exceeds maximum size")

        target = self._safe_target(filename)
        lock = self._target_lock(target)
        with lock:
            if target.exists() and not overwrite:
                raise UploadConflict(f"{target.name} already exists")

            tmp_path = self._write_temp_file(target, content)
            try:
                if tmp_path.stat().st_size != len(content):
                    raise UnsafeUpload("temporary upload size changed during write")
                if target.exists() and not overwrite:
                    raise UploadConflict(f"{target.name} already exists")
                os.replace(tmp_path, target)
            except Exception:
                tmp_path.unlink(missing_ok=True)
                raise
        return target

    def _write_temp_file(self, target: Path, content: bytes) -> Path:
        fd, tmp_name = tempfile.mkstemp(
            prefix=f".{target.name}.",
            suffix=".uploading",
            dir=self.upload_dir,
        )
        tmp_path = Path(tmp_name)
        try:
            with os.fdopen(fd, "wb") as handle:
                handle.write(content)
                handle.flush()
                os.fsync(handle.fileno())
        except Exception:
            tmp_path.unlink(missing_ok=True)
            raise
        return tmp_path


__all__ = ["AtomicUploadStore", "UnsafeUpload", "UploadConflict"]

