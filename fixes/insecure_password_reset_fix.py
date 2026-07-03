"""
Fix for Issue #93: Insecure Password Reset Token ($25)

Vulnerability:
    Password reset tokens generated with weak randomness, predictable
    patterns (timestamp-based), or excessively long validity periods.
    Attackers can brute-force or predict tokens to hijack accounts.

Fix:
    Use cryptographically secure random token generation (secrets module),
    bind tokens to user+timestamp+nonce, enforce short expiry, and
    implement rate limiting per user.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
import threading
import time
from typing import Dict, Optional, Set, Tuple


class SecurePasswordResetToken:
    """Cryptographically secure password reset token manager.

    Security properties:
        1. Tokens are generated using secrets.token_urlsafe (CSPRNG)
        2. Tokens are bound to the user identity (HMAC prevents forgery)
        3. Short expiry (default: 15 minutes)
        4. One-time use: consumed tokens cannot be reused
        5. Rate-limited per user (max 3 tokens per hour)
        6. All attempts are logged for audit
    """

    DEFAULT_EXPIRY_SECONDS = 15 * 60  # 15 minutes
    MAX_TOKENS_PER_HOUR = 3
    TOKEN_BYTES = 32  # 256 bits of entropy

    def __init__(self, secret_key: Optional[str] = None) -> None:
        self._secret = secret_key or secrets.token_hex(32)
        self._lock = threading.Lock()
        self._tokens: Dict[str, dict] = {}  # token_hash -> metadata
        self._user_requests: Dict[str, list[float]] = {}  # user -> timestamps
        self._consumed: Set[str] = set()
        self._audit_log: list[dict] = []

    def _hash_token(self, raw: str) -> str:
        return hashlib.sha256(raw.encode()).hexdigest()

    def _hmac_bind(self, user_id: str, token: str) -> str:
        """Bind token to user to prevent token reuse across accounts."""
        return hmac.new(
            self._secret.encode(),
            f"{user_id}:{token}".encode(),
            hashlib.sha256,
        ).hexdigest()

    def _check_rate_limit(self, user_id: str) -> Tuple[bool, int]:
        """Check if user has exceeded token request rate.

        Returns:
            (allowed, retry_after_seconds)
        """
        now = time.time()
        window_start = now - 3600  # 1 hour window

        timestamps = self._user_requests.get(user_id, [])
        # Prune old entries
        timestamps = [t for t in timestamps if t > window_start]
        self._user_requests[user_id] = timestamps

        if len(timestamps) >= self.MAX_TOKENS_PER_HOUR:
            oldest = timestamps[0]
            retry_after = int(3600 - (now - oldest))
            return False, max(retry_after, 1)

        return True, 0

    def generate(self, user_id: str, metadata: Optional[dict] = None) -> Optional[str]:
        """Generate a secure password reset token for the user.

        Returns:
            The raw token string (to be sent to user via email), or None
            if rate-limited.
        """
        allowed, retry_after = self._check_rate_limit(user_id)
        if not allowed:
            self._log("generate", user_id, False,
                      f"rate limited, retry in {retry_after}s")
            return None

        # Generate cryptographically secure random token
        raw_token = secrets.token_urlsafe(self.TOKEN_BYTES)

        # HMAC bind to user
        binding = self._hmac_bind(user_id, raw_token)
        token_hash = self._hash_token(raw_token)

        now = time.time()
        with self._lock:
            self._tokens[token_hash] = {
                "user_id": user_id,
                "binding": binding,
                "created_at": now,
                "expires_at": now + self.DEFAULT_EXPIRY_SECONDS,
                "used": False,
                "metadata": metadata or {},
            }
            # Record the request for rate limiting
            self._user_requests.setdefault(user_id, [])
            self._user_requests[user_id].append(now)

        self._log("generate", user_id, True)
        return raw_token

    def verify(self, user_id: str, raw_token: str) -> Tuple[bool, str]:
        """Verify a password reset token.

        Returns:
            (valid, error_message)
        """
        if not raw_token or not user_id:
            return False, "Missing token or user_id"

        token_hash = self._hash_token(raw_token)
        expected_binding = self._hmac_bind(user_id, raw_token)

        with self._lock:
            entry = self._tokens.get(token_hash)

            if not entry:
                self._log("verify", user_id, False, "token not found")
                return False, "Invalid or expired token"

            if entry["used"]:
                self._log("verify", user_id, False, "token already used")
                return False, "Token has already been used"

            if time.time() > entry["expires_at"]:
                self._log("verify", user_id, False, "token expired")
                return False, "Token has expired"

            if entry["user_id"] != user_id:
                self._log("verify", user_id, False, "user mismatch")
                return False, "Token does not match user"

            if not hmac.compare_digest(entry["binding"], expected_binding):
                self._log("verify", user_id, False, "HMAC mismatch")
                return False, "Token validation failed"

            # One-time use: mark as consumed
            entry["used"] = True
            self._consumed.add(token_hash)

        self._log("verify", user_id, True, "token verified successfully")
        return True, ""

    def consume(self, user_id: str, raw_token: str) -> Tuple[bool, str]:
        """Verify AND consume a token in one call (atomic)."""
        valid, msg = self.verify(user_id, raw_token)
        if valid:
            return True, "Password reset authorized"
        return False, msg

    def cleanup_expired(self) -> int:
        """Remove expired tokens from memory."""
        now = time.time()
        expired = [
            h for h, e in self._tokens.items()
            if now > e["expires_at"]
        ]
        for h in expired:
            del self._tokens[h]
        return len(expired)

    def _log(self, action: str, user_id: str, success: bool,
             detail: str = "") -> None:
        self._audit_log.append({
            "action": action,
            "user_id": user_id,
            "success": success,
            "detail": detail,
            "timestamp": time.time(),
        })

    def get_audit_log(self, user_id: Optional[str] = None,
                      limit: int = 100) -> list[dict]:
        logs = self._audit_log
        if user_id:
            logs = [e for e in logs if e["user_id"] == user_id]
        return logs[-limit:]


# --------------------------------------------------------------------- self-test
if __name__ == "__main__":
    pm = SecurePasswordResetToken()

    # Test 1: Generate and verify valid token
    token = pm.generate("user123")
    assert token is not None, "token should be generated"
    valid, msg = pm.verify("user123", token)
    assert valid, f"valid token should verify: {msg}"

    # Test 2: Token is one-time use
    valid2, msg2 = pm.verify("user123", token)
    assert not valid2, "token should be one-time use"

    # Test 3: Wrong user can't use token
    token2 = pm.generate("user456")
    valid3, msg3 = pm.verify("user999", token2)
    assert not valid3, "wrong user should not verify"

    # Test 4: Rate limiting
    for i in range(3):
        pm.generate("ratelimit_user")
    blocked = pm.generate("ratelimit_user")
    assert blocked is None, "rate limited user should get None"

    print("insecure_password_reset_fix self-test passed")
    print(f"  Token: {token[:16]}...")
    print(f"  Verify: {valid}")
    print(f"  Reuse blocked: {not valid2}")
    print(f"  Rate limit works: {blocked is None}")
