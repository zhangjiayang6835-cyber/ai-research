"""
Fix for Issue #948 — Python Pickle Deserialization RCE via Cache
==================================================================

Vulnerability
-------------
Redis cache stores user sessions serialized with pickle.dumps(). Attackers
write malicious pickle payloads to the cache. When the server calls
pickle.loads(), arbitrary code execution is triggered.

Fix Strategy
------------
1. Replace pickle with JSON serialization for all cache data.
2. If pickle must be used, add HMAC-SHA256 signature verification.
3. Sign cached data to prevent tampering.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
from typing import Any


def json_serialize(data: dict) -> str:
    return json.dumps(data, ensure_ascii=False, default=str)


def json_deserialize(data: str) -> dict:
    return json.loads(data)


def _get_signing_key() -> bytes:
    key = os.environ.get("CACHE_SIGNING_KEY")
    if key:
        return key.encode()
    return os.urandom(32)


def _sign_data(data: bytes, key: bytes | None = None) -> str:
    if key is None:
        key = _get_signing_key()
    return hmac.new(key, data, hashlib.sha256).hexdigest()


def secure_pickle_dumps(data: Any, key: bytes | None = None) -> bytes:
    import pickle
    pickled = pickle.dumps(data)
    signature = _sign_data(pickled, key)
    return f"{signature}:".encode() + pickled


def secure_pickle_loads(data: bytes, key: bytes | None = None) -> Any:
    import pickle
    if key is None:
        key = _get_signing_key()
    colon_idx = data.find(b":")
    if colon_idx == -1:
        raise ValueError("Invalid signed pickle format")
    signature = data[:colon_idx].decode()
    pickled_data = data[colon_idx + 1:]
    expected = _sign_data(pickled_data, key)
    if not hmac.compare_digest(signature, expected):
        raise ValueError("Cache data integrity check failed: signature mismatch")
    return pickle.loads(pickled_data)


class SafeSessionCache:
    """Cache that uses JSON serialization to prevent deserialization attacks."""

    def __init__(self, redis_client):
        self.redis = redis_client

    def set_session(self, session_id: str, data: dict, ttl: int = 3600) -> None:
        serialized = json_serialize(data)
        self.redis.setex(f"session:{session_id}", ttl, serialized)

    def get_session(self, session_id: str) -> dict | None:
        data = self.redis.get(f"session:{session_id}")
        if data is None:
            return None
        return json_deserialize(data)
