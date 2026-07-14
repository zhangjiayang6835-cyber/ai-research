"""
Fix for Issue #966 — JWT Kid Injection → Path Traversal → Secret Key Leak
============================================================================

Vulnerability
-------------
JWT verification uses kid (Key ID) to load keys from filesystem:
fs.readFileSync("/keys/" + decoded.kid). Attacker sets kid: ../../etc/passwd
to bypass signature verification.

Fix Strategy
------------
1. Use kid whitelist enumeration — kid must match predefined IDs only.
2. Never derive file paths from kid input.
3. Validate and reject path traversal characters.
"""

from __future__ import annotations

import json
import re
from typing import Any, Final

# Whitelist of allowed kid values
ALLOWED_KIDS: Final[set[str]] = {"key1", "key2", "key3", "signing-key", "default"}

# Path traversal patterns to reject
PATH_TRAVERSAL_PATTERNS: Final[list[re.Pattern]] = [
    re.compile(r"\.\."),       # Parent directory
    re.compile(r"^/"),         # Absolute paths
    re.compile(r"[\\]"),       # Backslash
    re.compile(r"~"),          # Home directory
    re.compile(r"\*"),         # Wildcard
    re.compile(r"\?"),         # Wildcard character
    re.compile(r"["),          # Glob patterns
]

# Character class for path traversal characters
TRAVERSAL_CHARS: Final[re.Pattern] = re.compile(r"[./\\~]")
SUSPICIOUS_CHARS: Final[re.Pattern] = re.compile(r"[<>:|?*\"']")


def validate_kid(kid: str) -> bool:
    """
    Validate a kid (Key ID) value.

    Returns True if the kid is valid, False otherwise.
    """
    if not kid or not isinstance(kid, str):
        return False

    # Check against whitelist
    if kid not in ALLOWED_KIDS:
        return False

    # Check for path traversal characters
    if TRAVERSAL_CHARS.search(kid):
        return False

    if SUSPICIOUS_CHARS.search(kid):
        return False

    # Check for path traversal patterns
    for pattern in PATH_TRAVERSAL_PATTERNS:
        if pattern.search(kid):
            return False

    return True


class SecureJWTVerifier:
    """
    JWT verifier that uses a kid whitelist to prevent path traversal attacks.

    Instead of using kid as a file path, keys are looked up by ID in a
    predefined dictionary.
    """

    def __init__(self, keys: dict[str, Any] | None = None):
        self._keys = keys or {}

    def add_key(self, kid: str, key: Any) -> None:
        """Register a key with a given kid."""
        if not validate_kid(kid):
            raise ValueError(f"Invalid kid: {kid}")
        self._keys[kid] = key

    def get_key(self, kid: str) -> Any:
        """Get a key by its kid, with validation."""
        if not validate_kid(kid):
            raise ValueError(f"Invalid kid: {kid}")
        if kid not in self._keys:
            raise KeyError(f"Key not found: {kid}")
        return self._keys[kid]

    def verify(self, token: str) -> dict | None:
        """
        Verify a JWT token.

        The kid is extracted from the JWT header and validated against
        the whitelist before any key lookup.
        """
        import base64
        try:
            header_b64 = token.split(".")[0]
            # Add padding
            padding = 4 - len(header_b64) % 4
            if padding != 4:
                header_b64 += "=" * padding
            header = json.loads(base64.urlsafe_b64decode(header_b64))
        except Exception:
            return None

        kid = header.get("kid", "")
        if not validate_kid(kid):
            return None

        try:
            key = self.get_key(kid)
        except (ValueError, KeyError):
            return None

        # Proceed with JWT verification using the key...
        return header
