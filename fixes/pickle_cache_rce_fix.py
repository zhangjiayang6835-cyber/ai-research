"""
Fix for Issue #659: Python Pickle Deserialization RCE via Cache.

Redis cache stores ``pickle.dumps()`` serialized user sessions.  An attacker
who can write to the cache (e.g. via a separate injection or misconfigured
Redis instance) can plant a malicious pickle payload.  When the application
later calls ``pickle.loads()`` on the cached value, the payload executes
arbitrary code on the server.

This module provides a **SafeCacheSerializer** that replaces pickle with:

1. **JSON** — for serialization of plain Python primitives (dict, list, str,
   int, float, bool, None).  JSON deserialization never executes code.

2. **HMAC-SHA256 signing** — every value written to the cache is signed with
   a secret key.  On read, the signature is verified.  Tampered or
   attacker-planted values are rejected before deserialization.

Usage::

    from fixes.pickle_cache_rce_fix import SafeCacheSerializer

    serializer = SafeCacheSerializer(secret_key="my-secret-key")

    # Write: instead of redis.set(key, pickle.dumps(session))
    redis.set(key, serializer.dumps(session))

    # Read: instead of pickle.loads(redis.get(key))
    session = serializer.loads(redis.get(key))
"""

from __future__ import annotations

import hashlib
import hmac
import json
import time
from typing import Any, Optional

__all__ = [
    "CacheSecurityError",
    "SafeCacheSerializer",
    "safe_cache_dumps",
    "safe_cache_loads",
]


# ---------------------------------------------------------------------------
# Exception
# ---------------------------------------------------------------------------


class CacheSecurityError(Exception):
    """Raised when cached data fails integrity or freshness checks."""


# ---------------------------------------------------------------------------
# SafeCacheSerializer
# ---------------------------------------------------------------------------


class SafeCacheSerializer:
    """Serialize/deserialize cache values safely using JSON + HMAC signing.

    Every value written to the cache is wrapped in a signed envelope::

        {
          "v": <JSON-serialized payload>,
          "t": <Unix timestamp>,
          "sig": <HMAC-SHA256 signature of v + t>
        }

    On read, the signature is verified before the payload is returned.
    This prevents:

    - **RCE via pickle**: JSON is used instead of pickle — no code execution.
    - **Cache poisoning**: Tampered values fail signature verification.
    - **Replay attacks**: Optional TTL prevents old values from being accepted.

    Parameters
    ----------
    secret_key:
        HMAC secret key.  Must be kept secret and at least 32 bytes.
    ttl_seconds:
        Optional maximum age of cached values.  Values older than this
        are rejected.  ``None`` disables TTL checking (default).
    """

    def __init__(
        self,
        secret_key: str | bytes,
        *,
        ttl_seconds: Optional[int] = None,
    ) -> None:
        if isinstance(secret_key, str):
            secret_key = secret_key.encode("utf-8")
        if len(secret_key) < 32:
            raise ValueError(
                "secret_key must be at least 32 bytes for HMAC-SHA256"
            )
        self._key = secret_key
        self._ttl = ttl_seconds

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def dumps(self, obj: Any) -> bytes:
        """Serialize *obj* to a signed cache envelope (bytes).

        Returns bytes suitable for storing in Redis, Memcached, etc.
        """
        payload = json.dumps(obj, ensure_ascii=False, separators=(",", ":"))
        return self._sign(payload)

    def loads(self, data: bytes) -> Any:
        """Deserialize a signed cache envelope back to a Python object.

        Raises :class:`CacheSecurityError` if the signature is invalid,
        the envelope is malformed, or the TTL has expired.
        """
        payload = self._verify(data)
        return json.loads(payload)

    # ------------------------------------------------------------------
    # Internal: signing & verification
    # ------------------------------------------------------------------

    def _sign(self, payload: str) -> bytes:
        """Create a signed envelope around *payload*."""
        now = int(time.time())
        message = f"{now}:{payload}".encode("utf-8")
        signature = hmac.new(
            self._key, message, digestmod=hashlib.sha256
        ).hexdigest()
        envelope = json.dumps(
            {"v": payload, "t": now, "sig": signature},
            ensure_ascii=False,
            separators=(",", ":"),
        )
        return envelope.encode("utf-8")

    def _verify(self, data: bytes) -> str:
        """Verify the signature on *data* and return the inner payload.

        Raises :class:`CacheSecurityError` on any verification failure.
        """
        if not isinstance(data, (bytes, bytearray)):
            raise CacheSecurityError(
                f"Expected bytes, got {type(data).__name__}"
            )

        # Parse envelope
        try:
            envelope = json.loads(data.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise CacheSecurityError(
                "Cache envelope is not valid JSON"
            ) from exc

        if not isinstance(envelope, dict):
            raise CacheSecurityError("Cache envelope must be a JSON object")

        payload = envelope.get("v")
        timestamp = envelope.get("t")
        signature = envelope.get("sig")

        if not all(
            isinstance(x, str) for x in (payload, signature)
        ) or not isinstance(timestamp, (int, float)):
            raise CacheSecurityError(
                "Cache envelope missing or has invalid 'v', 't', or 'sig' fields"
            )

        # Verify signature
        message = f"{int(timestamp)}:{payload}".encode("utf-8")
        expected_sig = hmac.new(
            self._key, message, digestmod=hashlib.sha256
        ).hexdigest()

        if not hmac.compare_digest(signature, expected_sig):
            raise CacheSecurityError(
                "Cache signature verification failed — data may have been tampered with"
            )

        # Check TTL
        if self._ttl is not None:
            age = int(time.time()) - int(timestamp)
            if age > self._ttl:
                raise CacheSecurityError(
                    f"Cache value expired (age {age}s > TTL {self._ttl}s)"
                )

        return payload


# ---------------------------------------------------------------------------
# Module-level convenience functions
# ---------------------------------------------------------------------------

_default_serializer: Optional[SafeCacheSerializer] = None


def configure(secret_key: str | bytes, *, ttl_seconds: Optional[int] = None) -> None:
    """Configure the module-level default serializer."""
    global _default_serializer
    _default_serializer = SafeCacheSerializer(
        secret_key, ttl_seconds=ttl_seconds
    )


def safe_cache_dumps(obj: Any) -> bytes:
    """Serialize *obj* using the configured default serializer.

    Raises :class:`RuntimeError` if :func:`configure` has not been called.
    """
    if _default_serializer is None:
        raise RuntimeError(
            "SafeCacheSerializer not configured. Call configure(secret_key) first."
        )
    return _default_serializer.dumps(obj)


def safe_cache_loads(data: bytes) -> Any:
    """Deserialize *data* using the configured default serializer.

    Raises :class:`RuntimeError` if :func:`configure` has not been called.
    """
    if _default_serializer is None:
        raise RuntimeError(
            "SafeCacheSerializer not configured. Call configure(secret_key) first."
        )
    return _default_serializer.loads(data)


# ---------------------------------------------------------------------------
# Self-tests
# ---------------------------------------------------------------------------


def _selftest() -> None:  # pragma: no cover
    import os
    import sys

    serializer = SafeCacheSerializer(secret_key=os.urandom(32))

    # 1. Round-trip
    obj = {"user": "alice", "role": "admin", "permissions": ["read", "write"]}
    data = serializer.dumps(obj)
    result = serializer.loads(data)
    assert result == obj, f"Round-trip failed: {result} != {obj}"

    # 2. Tampered data is rejected
    tampered = data[:-1] + b"x"
    try:
        serializer.loads(tampered)
        raise AssertionError("Tampered data was NOT rejected!")
    except CacheSecurityError:
        pass

    # 3. Wrong key cannot verify
    other = SafeCacheSerializer(secret_key=os.urandom(32))
    try:
        other.loads(data)
        raise AssertionError("Cross-key verification should have failed!")
    except CacheSecurityError:
        pass

    # 4. TTL enforcement
    ttl_serializer = SafeCacheSerializer(
        secret_key=os.urandom(32), ttl_seconds=0
    )
    ttl_data = ttl_serializer.dumps({"x": 1})
    import time
    time.sleep(1.1)
    try:
        ttl_serializer.loads(ttl_data)
        raise AssertionError("Expired data was NOT rejected!")
    except CacheSecurityError:
        pass

    # 5. Malformed envelope
    for bad in [b"not json", b"{}", b'{"v":"x"}' ]:
        try:
            serializer.loads(bad)
            raise AssertionError(f"Malformed envelope accepted: {bad!r}")
        except CacheSecurityError:
            pass

    # 6. Primitive types round-trip correctly
    for val in ["hello", 42, 3.14, True, None, [1, 2, 3], {"a": {"b": 1}}]:
        assert serializer.loads(serializer.dumps(val)) == val

    # 7. Module-level convenience functions
    configure(secret_key=os.urandom(32))
    d = safe_cache_dumps({"status": "ok"})
    assert safe_cache_loads(d) == {"status": "ok"}

    print("pickle_cache_rce_fix: all self-tests passed", file=sys.stderr)


if __name__ == "__main__":  # pragma: no cover
    _selftest()
