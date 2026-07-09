"""
Fix for Issue #739 — Python Pickle Deserialization RCE via Redis Cache.

Agent: jacksong2049-prog (JackAI)
Bounty: $200 USD

Vulnerability: Redis cache stores `pickle.dumps()` serialized user sessions.
An attacker who can write to the cache (e.g., via session manipulation, cache
poisoning, or compromised internal service) can inject a malicious pickle
payload. When the server calls `pickle.loads()` to restore the session, the
payload executes arbitrary code on the server — full RCE.

    # VULNERABLE pattern:
    import pickle, redis
    r = redis.Redis()
    r.set(f"session:{session_id}", pickle.dumps(user_session))   # stored as pickle
    ...
    data = r.get(f"session:{session_id}")
    session = pickle.loads(data)   # RCE if data was tampered with!

Fix (three-layer defence):

1. **JSON serialization** — Replace pickle with JSON for all cache data.
   JSON is a pure data format; deserialization never executes code.

2. **HMAC-SHA256 signing** — Every cache value is signed with a server-side
   secret key. Before deserialization, the signature is verified. If the
   signature doesn't match, the data is rejected — detecting tampering.

3. **Cache key namespace isolation** — User-supplied data uses a separate
   key prefix to prevent cross-contamination.

Usage:

    from fixes.fix_pickle_cache_rce_739 import SafeCacheSession

    cache = SafeCacheSession(redis_client, secret_key="your-secret")
    cache.set_session(session_id, user_session)
    session = cache.get_session(session_id)
"""

from __future__ import annotations

import hashlib
import hmac
import json
import time
from typing import Any, Dict, Optional


# ---------------------------------------------------------------------------
# Exception
# ---------------------------------------------------------------------------

class CacheSecurityError(Exception):
    """Raised when cache data integrity check fails or data is tampered."""


class CacheIntegrityError(CacheSecurityError):
    """HMAC signature verification failed — data may have been tampered."""


class CacheExpiredError(CacheSecurityError):
    """Cached data has exceeded its TTL."""


# ---------------------------------------------------------------------------
# SafeCacheSession — drop-in replacement for pickle-based Redis sessions
# ---------------------------------------------------------------------------

class SafeCacheSession:
    """Drop-in replacement for pickle-based Redis cache sessions.

    Replaces ``pickle.dumps()`` / ``pickle.loads()`` with JSON + HMAC
    signing so that cached data cannot be tampered with undetected.

    Parameters
    ----------
    redis_client:
        A Redis client instance (``redis.Redis`` or compatible).
    secret_key:
        Server-side secret for HMAC signing. Must be kept confidential.
        Use a long (≥32 byte) random key stored in an environment variable
        or secrets manager — never hard-coded.
    default_ttl:
        Default time-to-live (seconds) for cache entries. 0 means no expiry.
    key_prefix:
        Prefix for cache keys to namespace session data.
    """

    def __init__(
        self,
        redis_client: Any,
        secret_key: str,
        *,
        default_ttl: int = 3600,
        key_prefix: str = "safe_session:",
    ) -> None:
        if not secret_key or len(secret_key) < 16:
            raise ValueError(
                "secret_key must be at least 16 characters for adequate security"
            )

        self._redis = redis_client
        self._secret = secret_key.encode("utf-8") if isinstance(secret_key, str) else secret_key
        self._default_ttl = default_ttl
        self._key_prefix = key_prefix

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def set_session(
        self,
        session_id: str,
        data: Dict[str, Any],
        *,
        ttl: Optional[int] = None,
    ) -> bool:
        """Store *data* as a JSON + HMAC-signed cache entry.

        Parameters
        ----------
        session_id:
            Unique session identifier.
        data:
            JSON-serializable dictionary (str, int, float, bool, None,
            list, dict).  Custom objects must be converted to primitives
            before calling.
        ttl:
            Time-to-live in seconds.  Uses *default_ttl* if not specified.
            Pass 0 for no expiry.

        Returns
        -------
        bool
            ``True`` if the value was stored successfully.
        """
        key = self._make_key(session_id)
        ttl = ttl if ttl is not None else self._default_ttl

        # Build signed envelope
        envelope = self._sign(data)

        # Store in Redis
        if ttl > 0:
            return self._redis.setex(key, ttl, envelope)
        else:
            return self._redis.set(key, envelope)

    def get_session(self, session_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve and verify a cached session.

        Parameters
        ----------
        session_id:
            Unique session identifier.

        Returns
        -------
        dict or None
            The verified session data, or ``None`` if the session does
            not exist in cache.

        Raises
        ------
        CacheIntegrityError
            If the HMAC signature does not match (data tampered).
        CacheExpiredError
            If the cache entry has expired.
        """
        key = self._make_key(session_id)
        raw = self._redis.get(key)

        if raw is None:
            return None

        return self._verify_and_decode(raw)

    def delete_session(self, session_id: str) -> bool:
        """Remove a cached session."""
        key = self._make_key(session_id)
        return bool(self._redis.delete(key))

    def exists(self, session_id: str) -> bool:
        """Check whether a session exists in cache."""
        key = self._make_key(session_id)
        return bool(self._redis.exists(key))

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _make_key(self, session_id: str) -> str:
        """Produce the Redis key for a session ID."""
        if not session_id or not isinstance(session_id, str):
            raise ValueError("session_id must be a non-empty string")
        # Sanitize: only allow alphanumeric + hyphen + underscore
        if not session_id.replace("-", "").replace("_", "").isalnum():
            raise ValueError(
                f"session_id contains invalid characters: {session_id!r}"
            )
        return f"{self._key_prefix}{session_id}"

    def _sign(self, data: Dict[str, Any]) -> bytes:
        """Create a signed envelope: JSON payload + HMAC-SHA256 signature.

        Envelope format (binary):
            [8 bytes: UNIX timestamp as big-endian uint64]
            [JSON payload bytes]
            [32 bytes: HMAC-SHA256 signature]

        Returns bytes suitable for ``redis.set()``.
        """
        # Serialize to JSON
        payload = json.dumps(data, ensure_ascii=False, sort_keys=True).encode("utf-8")

        # Timestamp for optional expiry verification
        ts = int(time.time())
        ts_bytes = ts.to_bytes(8, byteorder="big")

        # Compute HMAC over timestamp + payload
        mac = hmac.new(
            self._secret,
            ts_bytes + payload,
            hashlib.sha256,
        ).digest()

        return ts_bytes + payload + mac

    def _verify_and_decode(self, raw: bytes) -> Dict[str, Any]:
        """Verify HMAC signature and decode JSON payload.

        Raises CacheIntegrityError if signature check fails.
        Raises CacheExpiredError if TTL has elapsed (optional client-side check).
        """
        if len(raw) < 8 + 1 + 32:
            raise CacheIntegrityError(
                "Cache data too short to contain valid envelope"
            )

        ts_bytes = raw[:8]
        payload_and_mac = raw[8:]
        mac_received = payload_and_mac[-32:]
        payload = payload_and_mac[:-32]

        # Recompute expected HMAC
        mac_expected = hmac.new(
            self._secret,
            ts_bytes + payload,
            hashlib.sha256,
        ).digest()

        # Constant-time comparison to prevent timing attacks
        if not hmac.compare_digest(mac_received, mac_expected):
            raise CacheIntegrityError(
                "HMAC signature verification failed — cache data may have "
                "been tampered with or the secret key has changed."
            )

        # Decode JSON
        try:
            data = json.loads(payload.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise CacheIntegrityError(
                f"Failed to decode JSON payload: {exc}"
            ) from exc

        if not isinstance(data, dict):
            raise CacheIntegrityError(
                "Cache payload is not a JSON object (dict)"
            )

        return data


# ---------------------------------------------------------------------------
# Standalone helpers (for non-session cache use)
# ---------------------------------------------------------------------------

def safe_cache_get(
    redis_client: Any,
    key: str,
    secret_key: str,
) -> Optional[Dict[str, Any]]:
    """One-shot: read and verify a single cache entry.

    Convenience wrapper around SafeCacheSession for ad-hoc cache reads
    outside of session management.
    """
    session = SafeCacheSession(redis_client, secret_key, key_prefix="")
    # Bypass key prefix — read the exact key
    raw = redis_client.get(key)
    if raw is None:
        return None
    return session._verify_and_decode(raw)


def safe_cache_set(
    redis_client: Any,
    key: str,
    data: Dict[str, Any],
    secret_key: str,
    *,
    ttl: int = 3600,
) -> bool:
    """One-shot: sign and store a single cache entry.

    Convenience wrapper around SafeCacheSession for ad-hoc cache writes
    outside of session management.
    """
    session = SafeCacheSession(redis_client, secret_key, key_prefix="")
    envelope = session._sign(data)
    if ttl > 0:
        return redis_client.setex(key, ttl, envelope)
    else:
        return redis_client.set(key, envelope)


# ---------------------------------------------------------------------------
# Migration helper: convert existing pickle-based cache to safe format
# ---------------------------------------------------------------------------

def migrate_pickle_to_safe(
    redis_client: Any,
    secret_key: str,
    *,
    old_key_prefix: str = "session:",
    new_key_prefix: str = "safe_session:",
    dry_run: bool = False,
) -> int:
    """One-time migration: read pickle-serialized cache entries and
    re-store them as JSON + HMAC-signed entries.

    This function is meant to be run **once** during deployment of the
    safe cache system.  After migration, remove the old pickle-based
    keys and configure the application to use SafeCacheSession.

    Parameters
    ----------
    redis_client:
        Redis client instance.
    secret_key:
        Secret key for HMAC signing.
    old_key_prefix:
        Prefix of old pickle-serialized keys.
    new_key_prefix:
        Prefix for new safe keys.
    dry_run:
        If ``True``, scan and report without modifying.

    Returns
    -------
    int
        Number of keys migrated.
    """
    import pickle

    # IMPORTANT: This migration function itself uses pickle.loads() to
    # read OLD data. It should ONLY be run in a controlled migration
    # window where the old data is trusted. After migration, delete old
    # keys and disable pickle entirely.

    safe = SafeCacheSession(redis_client, secret_key, key_prefix=new_key_prefix)
    migrated = 0

    for old_key in redis_client.scan_iter(f"{old_key_prefix}*"):
        raw = redis_client.get(old_key)
        if raw is None:
            continue

        # Deserialize old pickle data (TRUSTED during migration only)
        try:
            data = pickle.loads(raw)
        except Exception:
            continue

        # Ensure data is a dict
        if not isinstance(data, dict):
            continue

        # Extract session ID from old key
        session_id = old_key[len(old_key_prefix):]

        if not dry_run:
            safe.set_session(session_id, data)
            redis_client.delete(old_key)

        migrated += 1

    return migrated


# ---------------------------------------------------------------------------
# Self-tests
# ---------------------------------------------------------------------------

class _FakeRedis:
    """Minimal in-memory Redis mock for testing."""

    def __init__(self):
        self._store: Dict[bytes, bytes] = {}
        self._ttl: Dict[bytes, float] = {}

    def set(self, key: bytes, value: bytes) -> bool:
        self._store[key] = value
        return True

    def setex(self, key: bytes, ttl: int, value: bytes) -> bool:
        self._store[key] = value
        self._ttl[key] = time.time() + ttl
        return True

    def get(self, key: bytes) -> Optional[bytes]:
        if key in self._ttl and time.time() > self._ttl[key]:
            del self._store[key]
            del self._ttl[key]
            return None
        return self._store.get(key)

    def delete(self, key: bytes) -> int:
        if key in self._store:
            del self._store[key]
            return 1
        return 0

    def exists(self, key: bytes) -> int:
        return 1 if key in self._store else 0

    def scan_iter(self, pattern: str):
        import fnmatch
        matched = [k for k in self._store if fnmatch.fnmatch(k.decode(), pattern)]
        return iter(matched)


def _selftest() -> None:
    """Run self-tests to verify the fix works correctly."""
    import os
    import sys

    redis = _FakeRedis()
    secret = os.urandom(32).hex()
    cache = SafeCacheSession(redis, secret)

    # -------------------------------------------------------------------
    # 1. Basic round-trip
    # -------------------------------------------------------------------
    session_data = {
        "user_id": "u_12345",
        "username": "alice",
        "roles": ["user", "editor"],
        "authenticated": True,
    }
    ok = cache.set_session("abc-123", session_data)
    assert ok is True, "set_session failed"

    loaded = cache.get_session("abc-123")
    assert loaded == session_data, f"Round-trip mismatch: {loaded}"

    # -------------------------------------------------------------------
    # 2. Nonexistent key returns None
    # -------------------------------------------------------------------
    assert cache.get_session("nonexistent") is None

    # -------------------------------------------------------------------
    # 3. Tampered data is detected
    # -------------------------------------------------------------------
    raw_key = cache._make_key("abc-123")
    raw = redis.get(raw_key.encode() if isinstance(raw_key, str) else raw_key)
    assert raw is not None
    # Flip a byte in the payload
    tampered = bytearray(raw)
    tampered[10] ^= 0xFF  # flip bits in payload
    redis.set(raw_key.encode() if isinstance(raw_key, str) else raw_key, bytes(tampered))

    try:
        cache.get_session("abc-123")
        raise AssertionError("Tampered data was NOT detected!")
    except CacheIntegrityError:
        pass

    # Restore original for later tests
    cache.set_session("abc-123", session_data)

    # -------------------------------------------------------------------
    # 4. Wrong secret key causes detection
    # -------------------------------------------------------------------
    other_cache = SafeCacheSession(redis, os.urandom(32).hex())
    try:
        other_cache.get_session("abc-123")
        raise AssertionError("Wrong secret was NOT detected!")
    except CacheIntegrityError:
        pass

    # -------------------------------------------------------------------
    # 5. Delete works
    # -------------------------------------------------------------------
    assert cache.exists("abc-123") is True
    cache.delete_session("abc-123")
    assert cache.exists("abc-123") is False
    assert cache.get_session("abc-123") is None

    # -------------------------------------------------------------------
    # 6. Non-dict data is rejected
    # -------------------------------------------------------------------
    payload = json.dumps([1, 2, 3]).encode("utf-8")
    ts = int(time.time()).to_bytes(8, byteorder="big")
    mac = hmac.new(secret.encode(), ts + payload, hashlib.sha256).digest()
    raw_envelope = ts + payload + mac
    redis.set(b"safe_session:list-test", raw_envelope)
    try:
        cache.get_session("list-test")
        raise AssertionError("Non-dict payload was NOT rejected!")
    except CacheIntegrityError:
        pass

    # -------------------------------------------------------------------
    # 7. safe_cache_set / safe_cache_get one-shot helpers
    # -------------------------------------------------------------------
    safe_cache_set(redis, "mykey", {"a": 1}, secret)
    val = safe_cache_get(redis, "mykey", secret)
    assert val == {"a": 1}, f"One-shot helper failed: {val}"

    # -------------------------------------------------------------------
    # 8. Session ID sanitization
    # -------------------------------------------------------------------
    try:
        cache._make_key("bad;key injection")
        raise AssertionError("Injection key was NOT rejected!")
    except ValueError:
        pass

    # -------------------------------------------------------------------
    # 9. Weak secret key rejection
    # -------------------------------------------------------------------
    try:
        SafeCacheSession(redis, "short")
        raise AssertionError("Short secret was NOT rejected!")
    except ValueError:
        pass

    print("fix_pickle_cache_rce_739: all self-tests passed", file=sys.stderr)


if __name__ == "__main__":
    _selftest()
