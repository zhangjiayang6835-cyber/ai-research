"""
Fix for Issue #10 — Path Traversal in File Download
=====================================================

Vulnerability
-------------
File download endpoint trusts user-supplied filenames without
sanitization, allowing attackers to traverse directories and read
arbitrary files (e.g., ``../../etc/passwd``).

Fix Strategy
------------
1. Canonicalize the requested path using ``os.path.realpath()``.
2. Verify the resolved path is strictly within the allowed base
   directory (no symlink escapes).
3. Reject filenames containing ``..`` or absolute-path prefixes.
4. Return 403 for any traversal attempt.
"""

from __future__ import annotations

import os
from pathlib import PurePosixPath
from typing import Optional


ALLOWED_BASE = "/var/data"


def safe_download_path(user_filename: str) -> Optional[str]:
    """Return a safe, canonicalized path inside ALLOWED_BASE, or None."""
    # Reject absolute paths and path-traversal sequences early
    if ".." in user_filename or user_filename.startswith("/"):
        return None

    # Use PurePosixPath to normalize without filesystem access
    safe_name = PurePosixPath(user_filename).name  # strip dirs

    # Reject empty or non-printable names
    if not safe_name or not safe_name.isascii() or not safe_name.isprintable():
        return None

    full_path = os.path.join(ALLOWED_BASE, safe_name)
    resolved = os.path.realpath(full_path)

    # Ensure the resolved path is strictly inside the allowed base
    if not resolved.startswith(os.path.realpath(ALLOWED_BASE) + os.sep) and resolved != os.path.realpath(ALLOWED_BASE):
        return None

    return resolved
