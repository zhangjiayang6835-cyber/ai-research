"""
Fix for Issue #113: Weak Session ID Generation

VULNERABILITY
-------------
Many web apps generate session identifiers using predictable sources such as
`random.random()`, `time.time()`, `uuid.uuid1()` (which embeds the MAC address
and a timestamp), incremental counters, or short hex strings. These are all
guessable / brute-forceable and allow session hijacking.

FIX
---
Use the CSPRNG provided by the operating system via Python's `secrets` module
(PEP 506). `secrets.token_urlsafe(nbytes)` is the recommended primitive for
session tokens — it draws from `os.urandom` and is suitable for cryptographic
use. We additionally:

  * Enforce a minimum of 32 bytes (256 bits) of entropy — well above OWASP's
    64-bit minimum and the 128-bit best-practice recommendation.
  * Provide constant-time comparison to defend against timing attacks when
    validating a presented session ID against stored state.
  * Provide a SHA-256 fingerprint helper so the raw token never needs to be
    persisted at rest (store the digest, compare with `hmac.compare_digest`).
  * Expose secure cookie attribute defaults (HttpOnly, Secure, SameSite=Lax)
    so the fix covers the full session-handling surface, not just generation.

Drop-in usage
-------------
    from fixes.weak_session_id_fix import SecureSessionManager

    sessions = SecureSessionManager()
    sid = sessions.new_session(user_id=42)          # opaque, 256-bit token
    user_id = sessions.validate(sid)                # None if invalid/expired
    sessions.revoke(sid)

The class is dependency-free and works on any Python 3.6+ runtime.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
import threading
import time
from dataclasses import dataclass
from typing import Dict, Optional

# OWASP ASVS V3.2.2 — session tokens MUST have >= 64 bits of entropy.
# We default to 256 bits (32 bytes) which is current best practice.
_MIN_ENTROPY_BYTES = 32
_DEFAULT_TTL_SECONDS = 60 * 60 * 8  # 8 hours


def generate_session_id(nbytes: int = _MIN_ENTROPY_BYTES) -> str:
    """Return a cryptographically strong, URL-safe session identifier.

    Uses `secrets.token_urlsafe`, which is backed by `os.urandom` (a CSPRNG).
    Never use `random`, `uuid.uuid1`, timestamps, or counters for session IDs.
    """
    if nbytes < _MIN_ENTROPY_BYTES:
        raise ValueError(
            f"Session IDs require at least {_MIN_ENTROPY_BYTES} bytes "
            f"({_MIN_ENTROPY_BYTES * 8} bits) of entropy; got {nbytes}."
        )
    return secrets.token_urlsafe(nbytes)


def fingerprint(session_id: str) -> str:
    """Return a SHA-256 hex digest of a session ID for safe at-rest storage.

    Storing the digest (not the raw token) limits blast radius if the session
    store is leaked — an attacker cannot replay the tokens directly.
    """
    return hashlib.sha256(session_id.encode("utf-8")).hexdigest()


def constant_time_equals(a: str, b: str) -> bool:
    """Timing-attack-resistant comparison for session IDs / fingerprints."""
    return hmac.compare_digest(a.encode("utf-8"), b.encode("utf-8"))


# Recommended cookie attributes when emitting the session ID to a browser.
SECURE_COOKIE_ATTRS = {
    "httponly": True,    # block JS access (mitigates XSS exfiltration)
    "secure": True,      # HTTPS only
    "samesite": "Lax",   # CSRF mitigation; use "Strict" for high-risk apps
    "path": "/",
}


@dataclass
class _SessionRecord:
    user_id: object
    expires_at: float


class SecureSessionManager:
    """In-memory session store using cryptographically strong identifiers.

    Replace the storage backend with Redis / your database for production;
    the security-critical pieces (token generation, hashing, constant-time
    compare, TTL enforcement) carry over unchanged.
    """

    def __init__(self, ttl_seconds: int = _DEFAULT_TTL_SECONDS) -> None:
        self._ttl = ttl_seconds
        self._store: Dict[str, _SessionRecord] = {}
        self._lock = threading.Lock()

    def new_session(self, user_id: object) -> str:
        sid = generate_session_id()
        with self._lock:
            self._store[fingerprint(sid)] = _SessionRecord(
                user_id=user_id,
                expires_at=time.time() + self._ttl,
            )
        return sid

    def validate(self, session_id: Optional[str]) -> Optional[object]:
        if not session_id or not isinstance(session_id, str):
            return None
        key = fingerprint(session_id)
        with self._lock:
            rec = self._store.get(key)
            if rec is None:
                return None
            if rec.expires_at < time.time():
                self._store.pop(key, None)
                return None
            return rec.user_id

    def rotate(self, session_id: str) -> Optional[str]:
        """Issue a new ID for the same session (call after privilege change)."""
        user_id = self.validate(session_id)
        if user_id is None:
            return None
        self.revoke(session_id)
        return self.new_session(user_id)

    def revoke(self, session_id: str) -> None:
        with self._lock:
            self._store.pop(fingerprint(session_id), None)


# --------------------------------------------------------------------------- #
# Self-test — run `python fixes/weak_session_id_fix.py` to verify.
# --------------------------------------------------------------------------- #
if __name__ == "__main__":
    # 1. Tokens are unique, URL-safe, and >= 256 bits of entropy.
    tokens = {generate_session_id() for _ in range(10_000)}
    assert len(tokens) == 10_000, "session IDs must be unique"
    sample = next(iter(tokens))
    assert len(sample) >= 43, "token_urlsafe(32) is >= 43 chars"

    # 2. Manager round-trip.
    mgr = SecureSessionManager(ttl_seconds=2)
    sid = mgr.new_session(user_id="alice")
    assert mgr.validate(sid) == "alice"
    assert mgr.validate("attacker-guess") is None
    assert mgr.validate(None) is None

    # 3. Rotation invalidates the old token.
    new_sid = mgr.rotate(sid)
    assert new_sid and new_sid != sid
    assert mgr.validate(sid) is None
    assert mgr.validate(new_sid) == "alice"

    # 4. Revoke + expiry.
    mgr.revoke(new_sid)
    assert mgr.validate(new_sid) is None

    short = SecureSessionManager(ttl_seconds=0)
    expired = short.new_session("bob")
    time.sleep(0.01)
    assert short.validate(expired) is None

    # 5. Constant-time compare works for equal and unequal inputs.
    assert constant_time_equals("abc", "abc")
    assert not constant_time_equals("abc", "abd")

    # 6. Weak request is rejected.
    try:
        generate_session_id(nbytes=4)
    except ValueError:
        pass
    else:
        raise AssertionError("weak entropy request should raise")

    print("OK - weak_session_id_fix self-tests passed")
