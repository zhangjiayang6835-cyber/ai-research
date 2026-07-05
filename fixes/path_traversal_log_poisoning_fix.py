"""Defense-in-depth fix for issue #334: path traversal plus log poisoning.

The vulnerable chain has two parts:

* user-controlled file paths escape an intended base directory; and
* attacker-controlled log fields inject new log lines or terminal controls.

This module provides framework-neutral helpers for resolving paths under a
trusted root and emitting single-line structured log records.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any
from urllib.parse import unquote


class PathTraversalLogPoisoningError(ValueError):
    """Raised when path or log input fails security validation."""


_CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f]")
_LOG_KEY = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")
_MAX_DECODE_PASSES = 3


def _decode_path(value: str) -> str:
    """Decode repeated URL encoding so %252e%252e%252f cannot bypass checks."""

    decoded = value
    for _ in range(_MAX_DECODE_PASSES):
        next_value = unquote(decoded)
        if next_value == decoded:
            break
        decoded = next_value
    return decoded


def resolve_safe_path(base_dir: str | Path, user_path: str) -> Path:
    """Return a resolved path only when it stays under ``base_dir``.

    The function rejects absolute paths, drive-qualified paths, traversal
    segments, null bytes, and URL-encoded traversal attempts before resolving
    the final target. The target does not need to exist, which keeps the helper
    useful for safe write paths as well as reads.
    """

    if not user_path or "\x00" in user_path:
        raise PathTraversalLogPoisoningError("Invalid path")

    decoded = _decode_path(user_path).replace("\\", "/")
    candidate_user_path = Path(decoded)

    if candidate_user_path.is_absolute() or candidate_user_path.drive:
        raise PathTraversalLogPoisoningError("Absolute paths are not allowed")

    if any(part in {"", ".", ".."} for part in decoded.split("/")):
        raise PathTraversalLogPoisoningError("Path traversal is not allowed")

    root = Path(base_dir).resolve()
    candidate = (root / candidate_user_path).resolve()

    try:
        candidate.relative_to(root)
    except ValueError as exc:
        raise PathTraversalLogPoisoningError("Path escapes base directory") from exc

    return candidate


def read_text_under_base(
    base_dir: str | Path,
    user_path: str,
    *,
    encoding: str = "utf-8",
    max_bytes: int = 1024 * 1024,
) -> str:
    """Safely read a text file from an allowed base directory.

    Size limiting prevents an attacker from using a legitimate in-tree path as
    a resource exhaustion primitive after traversal has been blocked.
    """

    target = resolve_safe_path(base_dir, user_path)
    if not target.is_file():
        raise PathTraversalLogPoisoningError("File does not exist")
    if target.stat().st_size > max_bytes:
        raise PathTraversalLogPoisoningError("File exceeds maximum size")
    return target.read_text(encoding=encoding)


def sanitize_log_value(value: Any, *, max_length: int = 2048) -> str:
    """Return a log-safe string without raw controls or injected new lines."""

    text = str(value)
    text = _CONTROL_CHARS.sub(lambda match: f"\\u{ord(match.group(0)):04x}", text)
    if len(text) > max_length:
        return text[:max_length] + "...[truncated]"
    return text


def structured_log_line(event: str, **fields: Any) -> str:
    """Build a single-line JSON log entry from untrusted field values."""

    if not _LOG_KEY.fullmatch(event):
        raise PathTraversalLogPoisoningError("Invalid event name")

    record: dict[str, Any] = {"event": event}
    for key, value in fields.items():
        if not _LOG_KEY.fullmatch(key):
            raise PathTraversalLogPoisoningError(f"Invalid log field: {key}")
        record[key] = sanitize_log_value(value)

    return json.dumps(record, ensure_ascii=True, separators=(",", ":"), sort_keys=True)


__all__ = [
    "PathTraversalLogPoisoningError",
    "read_text_under_base",
    "resolve_safe_path",
    "sanitize_log_value",
    "structured_log_line",
]
