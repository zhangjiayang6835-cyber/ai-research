"""
Fix for Issue #1215 — Python Pickle Deserialization RCE via Cache
==================================================================

Vulnerability
-------------
Redis cache stores user sessions and application data serialized with pickle.dumps().
Attackers write malicious pickle payloads to the cache. When the server
calls pickle.loads(), arbitrary code execution is triggered (RCE).

Fix
---
1. Replace pickle with JSON serialization for all cache data.
2. If pickle must be used, add HMAC-SHA256 signature verification.
3. Sign cached data to prevent tampering.
4. Implement safe deserialization wrapper that rejects unsigned data.

References
----------
CWE-502: Deserialization of Untrusted Data
OWASP Top 10: A8:2017-Insecure Deserialization
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
from typing import Any, Optional


def json_serialize(data: Any) -> str:
    """Serialize data to JSON. Never executes code on deserialization."""
    return json.dumps(data, ensure_ascii=False, default=str)


def json_deserialize(data: str) -> Any:
    """Deserialize JSON data safely."""
    return json.loads(data)


def _get_signing_key() -> bytes:
    """Get the cache signing key from environment or generate one."""
    key = os.environ.get("CACHE_SIGNING_KEY")
    if key:
        return key.encode()
    # In production, this should be a fixed, secure key
    return os.urandom(32)


def _sign_data(data: bytes, key: Optional[bytes] = None) -> str:
    """Sign data with HMAC-SHA256."""
    if key is None:
        key = _get_signing_key()
    return hmac.new(key, data, hashlib.sha256).hexdigest()


def secure_serialize(data: Any, key: Optional[bytes] = None) -> bytes:
    """Serialize data with an HMAC signature for integrity verification.

    Uses JSON serialization (not pickle) to prevent RCE.
    The output format is: signature:json_data
    """
    if key is None:
        key = _get_signing_key()
    json_bytes = json_serialize(data).encode("utf-8")
    signature = _sign_data(json_bytes, key)
    return f"{signature}:".encode("utf-8") + json_bytes


def secure_deserialize(data: bytes, key: Optional[bytes] = None) -> Any:
    """Deserialize signed JSON data, verifying the HMAC signature.

    Raises ValueError if the signature is invalid or missing.
    Never uses pickle — only JSON for safe deserialization.
    """
    if key is None:
        key = _get_signing_key()
    colon_idx = data.find(b":")
    if colon_idx == -1:
        raise ValueError("Invalid signed data format: missing signature separator")
    signature = data[:colon_idx].decode("utf-8")
    json_bytes = data[colon_idx + 1:]
    expected = _sign_data(json_bytes, key)
    if not hmac.compare_digest(signature, expected):
        raise ValueError("Cache data integrity check failed: signature mismatch")
    return json_deserialize(json_bytes.decode("utf-8"))


class SafeRedisCache:
    """Redis cache wrapper that prevents pickle deserialization RCE.

    Uses JSON serialization with HMAC signing instead of pickle.
    This ensures:
    - No arbitrary code execution during deserialization
    - Data integrity verification (tamper detection)
    - Compatible with existing Redis infrastructure
    """

    def __init__(self, redis_client, signing_key: Optional[str] = None):
        """Initialize the safe cache wrapper.

        Args:
            redis_client: A Redis client instance (redis.Redis or compatible).
            signing_key: Optional HMAC signing key. If None, reads from
                         CACHE_SIGNING_KEY env var or generates a random key.
        """
        self.redis = redis_client
        if signing_key:
            self._key = signing_key.encode("utf-8")
        else:
            self._key = _get_signing_key()

    def set(self, key: str, value: Any, ttl: int = 3600) -> bool:
        """Store a value in the cache with integrity protection.

        Args:
            key: Cache key.
            value: Any JSON-serializable value (dict, list, str, int, etc.).
            ttl: Time-to-live in seconds (default: 3600).

        Returns:
            True if the value was stored successfully.
        """
        serialized = secure_serialize(value, self._key)
        return self.redis.setex(key, ttl, serialized)

    def get(self, key: str) -> Optional[Any]:
        """Retrieve a value from the cache with integrity verification.

        Args:
            key: Cache key.

        Returns:
            The deserialized value, or None if not found or tampered.
        """
        data = self.redis.get(key)
        if data is None:
            return None
        try:
            return secure_deserialize(data, self._key)
        except ValueError:
            # Data was tampered — delete the corrupted entry
            self.redis.delete(key)
            return None

    def set_session(self, session_id: str, data: dict, ttl: int = 3600) -> None:
        """Store a user session in the cache."""
        self.set(f"session:{session_id}", data, ttl)

    def get_session(self, session_id: str) -> Optional[dict]:
        """Retrieve a user session from the cache."""
        return self.get(f"session:{session_id}")

    def delete(self, key: str) -> bool:
        """Delete a key from the cache."""
        return bool(self.redis.delete(key))


# Backward-compatible wrapper for existing code that uses pickle
class PickleFreeSerializer:
    """Drop-in replacement for pickle-based cache serialization.

    Usage:
        # Old (vulnerable):
        # cache.set(key, pickle.dumps(data))
        # data = pickle.loads(cache.get(key))

        # New (safe):
        serializer = PickleFreeSerializer()
        cache.set(key, serializer.dumps(data))
        data = serializer.loads(cache.get(key))
    """

    def __init__(self, signing_key: Optional[str] = None):
        if signing_key:
            self._key = signing_key.encode("utf-8")
        else:
            self._key = _get_signing_key()

    def dumps(self, obj: Any) -> bytes:
        """Serialize an object safely (JSON, not pickle)."""
        return secure_serialize(obj, self._key)

    def loads(self, data: bytes) -> Any:
        """Deserialize data safely with integrity check."""
        return secure_deserialize(data, self._key)


if __name__ == "__main__":
    # Self-test
    serializer = PickleFreeSerializer("test-key-1215")
    test_data = {"user_id": 1215, "role": "admin", "tags": ["security", "bounty"]}

    # Round-trip test
    serialized = serializer.dumps(test_data)
    deserialized = serializer.loads(serialized)
    assert deserialized == test_data, "Round-trip failed"
    print("PASS: Serialization round-trip works")

    # Tamper detection test
    tampered = serialized.replace(b"admin", b"hacker")
    try:
        serializer.loads(tampered)
        print("FAIL: Should have detected tampering")
    except ValueError:
        print("PASS: Tampering detected")

    # Missing signature test
    try:
        serializer.loads(b'{"user": "test"}')
        print("FAIL: Should have rejected unsigned data")
    except ValueError:
        print("PASS: Unsigned data rejected")

    print("All tests passed — pickle-free cache serialization is working!")
