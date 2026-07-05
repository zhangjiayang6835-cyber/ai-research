"""Path traversal resistant download helper for issue #88.

The vulnerable pattern is joining an attacker supplied path to a download
directory and trusting string prefixes. This module decodes URL-encoded input,
rejects absolute paths and traversal segments, resolves the final target, and
serves it only if the resolved file remains under the configured base directory.
"""

from __future__ import annotations

import os
import re
from pathlib import Path, PurePosixPath, PureWindowsPath
from urllib.parse import unquote


SAFE_SEGMENT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._ -]{0,127}$")


class UnsafeDownloadPath(ValueError):
    """Raised when a requested download path is unsafe."""


class DownloadNotFound(FileNotFoundError):
    """Raised when a safe path does not point at a downloadable file."""


class SafeDownloadStore:
    """Resolve and read downloadable files without path traversal."""

    def __init__(self, base_dir: str | os.PathLike[str]) -> None:
        self.base_dir = Path(base_dir).resolve()
        self.base_dir.mkdir(parents=True, exist_ok=True)

    def resolve(self, user_path: str) -> Path:
        """Return a canonical path under ``base_dir`` or raise.

        The check happens after URL decoding and after filesystem resolution so
        encoded traversal and symlink escapes are both blocked.
        """

        decoded = self._decode_user_path(user_path)
        parts = self._safe_parts(decoded)
        candidate = self.base_dir.joinpath(*parts).resolve()
        try:
            candidate.relative_to(self.base_dir)
        except ValueError as exc:
            raise UnsafeDownloadPath("requested file escapes the download directory") from exc
        return candidate

    def read_bytes(self, user_path: str) -> bytes:
        target = self.resolve(user_path)
        if not target.exists() or not target.is_file():
            raise DownloadNotFound("download target is not a regular file")
        return target.read_bytes()

    @staticmethod
    def _decode_user_path(user_path: str) -> str:
        if not isinstance(user_path, str):
            raise UnsafeDownloadPath("download path must be text")
        value = user_path.strip()
        for _ in range(4):
            decoded = unquote(value)
            if decoded == value:
                break
            value = decoded
        if not value:
            raise UnsafeDownloadPath("download path is empty")
        if "\x00" in value or any(ord(ch) < 32 for ch in value):
            raise UnsafeDownloadPath("download path contains control characters")
        return value

    @staticmethod
    def _safe_parts(decoded_path: str) -> tuple[str, ...]:
        if "\\" in decoded_path:
            raise UnsafeDownloadPath("backslash path separators are not accepted")
        if PurePosixPath(decoded_path).is_absolute() or PureWindowsPath(decoded_path).is_absolute():
            raise UnsafeDownloadPath("absolute paths are not accepted")
        if ":" in decoded_path:
            raise UnsafeDownloadPath("drive and stream syntax is not accepted")

        raw_parts = PurePosixPath(decoded_path).parts
        parts: list[str] = []
        for part in raw_parts:
            if part in {"", "."}:
                continue
            if part == "..":
                raise UnsafeDownloadPath("parent directory traversal is not accepted")
            if not SAFE_SEGMENT_RE.fullmatch(part):
                raise UnsafeDownloadPath("download path contains unsupported characters")
            parts.append(part)
        if not parts:
            raise UnsafeDownloadPath("download path has no file component")
        return tuple(parts)


__all__ = ["SafeDownloadStore", "UnsafeDownloadPath", "DownloadNotFound"]

