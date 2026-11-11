"""
Fix for Issue #719 — Predictable OAuth State Token → CSRF + Account Takeover

Vulnerability
-------------
The OAuth state parameter was generated using predictable values (auto-increment
integers or timestamps). An attacker could predict the next state value, craft a
malicious OAuth authorization URL, and trick a victim into clicking it. When the
victim authorizes, the attacker's account becomes linked to the victim's session,
resulting in account takeover.

Fix
---
1. Use secrets.token_urlsafe(32) for cryptographically random state tokens
2. Bind state to user session via HMAC-SHA256 signature
3. Single-use state enforcement (token expires after first verification)
4. Time-bound state validity (10-minute TTL)
5. Constant-time comparison via hmac.compare_digest

Acceptance Criteria
-------------------
- [x] Uses cryptographically secure random number generator
- [x] State token is at least 16 bytes (32 bytes used)
- [x] State is bound to user session and single-use
"""

from __future__ import annotations

import hmac
import hashlib
import secrets
import time
from typing import Optional


class SecureOAuthState:
    """
    OAuth state token manager with cryptographic security.

    Features:
    - 32-byte random tokens via secrets.token_urlsafe
    - HMAC-SHA256 signature bound to session ID
    - Single-use enforcement with in-memory set
    - 10-minute time-to-live
    - Constant-time verification
    """

    def __init__(self, secret_key: bytes | None = None):
        self._secret_key = secret_key or secrets.token_bytes(32)
        self._used_states: set[str] = set()

    def generate_state(self, session_id: str) -> str:
        """
        Generate a cryptographically secure OAuth state token.

        The token contains:
        - 32-byte random payload (URL-safe base64)
        - Unix timestamp for TTL enforcement
        - HMAC-SHA256 signature binding the token to the session

        Args:
            session_id: The user's current session identifier.

        Returns:
            A URL-safe state string in the format: random.timestamp.signature
        """
        random_part = secrets.token_urlsafe(32)
        timestamp = str(int(time.time()))
        message = f"{random_part}:{timestamp}:{session_id}".encode()
        signature = hmac.new(
            self._secret_key, message, hashlib.sha256
        ).hexdigest()[:16]
        return f"{random_part}.{timestamp}.{signature}"

    def verify_state(self, state: str, session_id: str, max_age: int = 600) -> bool:
        """
        Verify an OAuth state token.

        Checks performed:
        1. Token format validation (3 dot-separated parts)
        2. HMAC signature verification (constant-time)
        3. Session binding (signature includes session_id)
        4. Time-to-live (default 600 seconds / 10 minutes)
        5. Single-use enforcement (replay protection)

        Args:
            state: The state string received from the OAuth callback.
            session_id: The user's current session identifier.
            max_age: Maximum token age in seconds (default 600).

        Returns:
            True if the token is valid, fresh, and unused; False otherwise.
        """
        try:
            random_part, timestamp, signature = state.split(".")
        except (ValueError, AttributeError):
            return False

        # Replay protection — reject already-used tokens
        if state in self._used_states:
            return False

        # Verify HMAC signature (constant-time)
        expected_sig = hmac.new(
            self._secret_key,
            f"{random_part}:{timestamp}:{session_id}".encode(),
            hashlib.sha256,
        ).hexdigest()[:16]

        if not hmac.compare_digest(signature, expected_sig):
            return False

        # Verify TTL
        age = time.time() - int(timestamp)
        if age < 0 or age > max_age:
            return False

        # Mark as used (single-use enforcement)
        self._used_states.add(state)

        # Limit memory growth — purge old entries periodically
        if len(self._used_states) > 10000:
            self._used_states.clear()

        return True

    def mark_used(self, state: str) -> None:
        """Explicitly mark a state as used (e.g., after callback processing)."""
        self._used_states.add(state)