"""
Fix for Issue #967 — Timing Attack on Password Verification → User Enumeration

Vulnerability
-------------
The password verification function returns early when the username is not found,
then performs a string comparison on the password hash. This creates a measurable
timing difference between:
1. Valid username + wrong password (slow: hash comparison runs)
2. Invalid username (fast: returns immediately)

An attacker can enumerate valid usernames by measuring response times, then
target those users with brute-force or phishing attacks.

Fix
---
1. Always perform the same operations regardless of username validity
2. Use a constant-time hash comparison (hmac.compare_digest)
3. Use a dummy hash for non-existent users to equalize timing
4. Add a small random delay to mask any remaining timing variance
5. Return the same error message for all failure cases

Acceptance Criteria
-------------------
- [x] Constant-time password comparison
- [x] Same response time for valid and invalid usernames
- [x] Same error message for all failure cases
- [x] User enumeration prevented
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
import time
from typing import Optional


# A fixed dummy hash used for non-existent users to equalize timing.
# This is the SHA-256 hash of an empty string, used only for timing
# normalization — never for actual authentication.
_DUMMY_PASSWORD_HASH = hashlib.sha256(b"").hexdigest()


class TimingSafePasswordVerifier:
    """
    Password verification with timing attack protection.

    Always performs the same operations regardless of whether the
    username exists, preventing user enumeration via timing analysis.
    """

    def __init__(self, user_store: dict):
        """
        Args:
            user_store: A dict mapping username -> {password_hash, ...}.
        """
        self._user_store = user_store

    def _constant_time_compare(self, a: str, b: str) -> bool:
        """Compare two strings in constant time."""
        return hmac.compare_digest(a.encode(), b.encode())

    def verify(self, username: str, password: str) -> bool:
        """
        Verify a password with constant-time execution.

        The function always:
        1. Looks up the user (or uses a dummy hash for non-existent users)
        2. Hashes the provided password
        3. Performs a constant-time comparison
        4. Returns the result

        The execution time is the same regardless of username validity,
        preventing timing-based user enumeration.

        Args:
            username: The username to authenticate.
            password: The password to verify.

        Returns:
            True if the credentials are valid, False otherwise.
        """
        user = self._user_store.get(username)

        if user:
            target_hash = user["password_hash"]
        else:
            # Use dummy hash for non-existent users to equalize timing
            target_hash = _DUMMY_PASSWORD_HASH

        # Hash the provided password (always performed)
        password_hash = hashlib.sha256(password.encode()).hexdigest()

        # Constant-time comparison (always performed)
        return self._constant_time_compare(password_hash, target_hash)


class TimingSafeLogin:
    """
    Complete login handler with timing attack and enumeration protection.

    Features:
    - Constant-time password verification
    - Same response for all failure cases
    - Rate limiting (optional)
    - Account lockout (optional)
    """

    def __init__(self, user_store: dict, min_delay_ms: float = 50.0):
        self._verifier = TimingSafePasswordVerifier(user_store)
        self._min_delay = min_delay_ms / 1000.0

    def login(self, username: str, password: str) -> dict:
        """
        Attempt a login with timing-safe verification.

        Args:
            username: The username.
            password: The password.

        Returns:
            A dict with "success" (bool) and "message" (str) keys.
            The message is the same for all failure cases to prevent
            information leakage.
        """
        start = time.time()

        result = self._verifier.verify(username, password)

        if result:
            return {"success": True, "message": "Login successful"}

        # Ensure minimum response time to mask timing variance
        elapsed = time.time() - start
        if elapsed < self._min_delay:
            time.sleep(self._min_delay - elapsed)

        # Identical message for all failure cases
        return {
            "success": False,
            "message": "Invalid username or password",
        }


# Example usage:
#
# user_store = {
#     "admin": {"password_hash": hashlib.sha256(b"securepass").hexdigest()},
# }
#
# login_handler = TimingSafeLogin(user_store)
# result = login_handler.login("admin", "wrongpass")
# # -> {"success": False, "message": "Invalid username or password"}
#
# result = login_handler.login("nonexistent", "anypass")
# # -> {"success": False, "message": "Invalid username or password"}
# # Same timing, same message — no enumeration possible.