"""TOCTOU-safe /tmp file handling for issue #1503.

The vulnerable pattern checks whether a predictable path such as ``/tmp/lock`` or
``/tmp/job_<id>`` exists and then opens it for writing. An attacker can replace
that path with a symlink between the check and the write, causing arbitrary
file overwrite.

This module closes the race by using atomic creation (``mkstemp`` or
``O_CREAT | O_EXCL``) so the check and use happen in a single syscall.
"""

from __future__ import annotations

import os
import stat
import tempfile
from pathlib import Path
from typing import BinaryIO


class ToctouSecurityError(PermissionError):
    """Raised when a temp file fails ownership or permission checks."""


def _verify_secure_fd(fd: int, path: str) -> None:
    """Ensure the opened descriptor is owned by us and mode 0600."""
    st = os.fstat(fd)
    if st.st_uid != os.getuid():
        os.close(fd)
        os.unlink(path)
        raise ToctouSecurityError(
            f"temporary file {path} is not owned by the current user"
        )

    mode = stat.S_IMODE(st.st_mode)
    expected = stat.S_IRUSR | stat.S_IWUSR
    if mode != expected:
        os.close(fd)
        os.unlink(path)
        raise ToctouSecurityError(
            f"temporary file {path} has insecure permissions {oct(mode)}"
        )


def create_secure_temp_file(
    data: bytes,
    *,
    prefix: str = "job_",
    suffix: str = "",
    directory: str | os.PathLike[str] | None = None,
) -> str:
    """Atomically create a private temp file and write ``data`` to it."""
    if not isinstance(data, bytes):
        raise TypeError("data must be bytes")

    fd, path = tempfile.mkstemp(prefix=prefix, suffix=suffix, dir=directory)
    try:
        _verify_secure_fd(fd, path)
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
    except Exception:
        try:
            os.unlink(path)
        except OSError:
            pass
        raise
    return path


def create_named_lock(lock_path: str | os.PathLike[str]) -> int:
    """Atomically create ``lock_path`` with ``O_CREAT | O_EXCL``."""
    path = os.fspath(lock_path)
    parent = os.path.dirname(path) or "."
    os.makedirs(parent, exist_ok=True)

    try:
        fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_RDWR, 0o600)
    except FileExistsError as exc:
        raise FileExistsError(
            f"lock already exists: {path}"
        ) from exc

    try:
        _verify_secure_fd(fd, path)
    except Exception:
        os.close(fd)
        os.unlink(path)
        raise
    return fd


def release_named_lock(lock_path: str | os.PathLike[str], fd: int | None = None) -> None:
    """Close and unlink a lock created by :func:`create_named_lock`."""
    if fd is not None:
        try:
            os.close(fd)
        except OSError:
            pass
    try:
        os.unlink(os.fspath(lock_path))
    except FileNotFoundError:
        pass


class SecureTempFile:
    """Context manager for atomic temp file creation and cleanup."""

    def __init__(
        self,
        *,
        prefix: str = "job_",
        suffix: str = "",
        directory: str | os.PathLike[str] | None = None,
    ) -> None:
        self.prefix = prefix
        self.suffix = suffix
        self.directory = directory
        self.fd: int | None = None
        self.path: str | None = None

    def __enter__(self) -> SecureTempFile:
        self.fd, self.path = tempfile.mkstemp(
            prefix=self.prefix,
            suffix=self.suffix,
            dir=self.directory,
        )
        _verify_secure_fd(self.fd, self.path)
        return self

    def write(self, data: bytes) -> None:
        if self.fd is None:
            raise RuntimeError("secure temp file is not open")
        os.write(self.fd, data)
        os.fsync(self.fd)

    def open_writer(self) -> BinaryIO:
        if self.fd is None or self.path is None:
            raise RuntimeError("secure temp file is not open")
        return os.fdopen(self.fd, "wb")

    def __exit__(self, exc_type, exc, tb) -> None:
        if self.fd is not None:
            try:
                os.close(self.fd)
            except OSError:
                pass
            self.fd = None
        if self.path:
            try:
                os.unlink(self.path)
            except FileNotFoundError:
                pass
            self.path = None


__all__ = [
    "SecureTempFile",
    "ToctouSecurityError",
    "create_named_lock",
    "create_secure_temp_file",
    "release_named_lock",
]
