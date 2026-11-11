"""
Fix for Issue #948 — Python Pickle Deserialization RCE via Cache

Vulnerability
-------------
Redis cache stores pickle.dumps()-serialized user sessions. Attacker writes
malicious pickle payload to cache; server deserializes with pickle.loads(),
triggering arbitrary code execution.

Fix
---
- Replace pickle with JSON serialization for untrusted data
- Add HMAC signature verification for integrity
- Use alternative safe serialization (msgpack, json)
"""

import json
import hmac
import hashlib
import os
from typing import Any, Optional


class SecureCacheSerializer:
    """Secure cache serializer that prevents pickle deserialization attacks."""

    def __init__(self, secret_key: Optional[str] = None):
        self.secret_key = secret_key or os.urandom(32).hex()
        self._key = self.secret_key.encode() if isinstance(self.secret_key, str) else self.secret_key

    def serialize(self, data: Any) -> str:
        payload = json.dumps(data, separators=(',', ':'))
        signature = hmac.new(self._key, payload.encode(), hashlib.sha256).hexdigest()
        return json.dumps({"data": data, "sig": signature}, separators=(',', ':'))

    def deserialize(self, data_str: str) -> Any:
        try:
            wrapped = json.loads(data_str)
            payload = wrapped.get("data")
            signature = wrapped.get("sig")
            if not signature:
                raise ValueError("Missing signature")
            payload_json = json.dumps(payload, separators=(',', ':'))
            expected = hmac.new(self._key, payload_json.encode(), hashlib.sha256).hexdigest()
            if not hmac.compare_digest(expected, signature):
                raise ValueError("Invalid signature - data may be tampered")
            return payload
        except (json.JSONDecodeError, KeyError) as e:
            raise ValueError(f"Invalid cache data format: {e}")


class PickleFreeRedisCache:
    """Redis cache wrapper that never uses pickle."""

    def __init__(self, redis_client, serializer: SecureCacheSerializer):
        self.redis = redis_client
        self.serializer = serializer

    def set(self, key: str, value: Any, ttl: int = 3600) -> bool:
        serialized = self.serializer.serialize(value)
        return self.redis.setex(key, ttl, serialized)

    def get(self, key: str) -> Optional[Any]:
        data = self.redis.get(key)
        if data is None:
            return None
        try:
            return self.serializer.deserialize(data)
        except ValueError:
            self.redis.delete(key)
            return None


if __name__ == "__main__":
    serializer = SecureCacheSerializer("test-secret-key-12345")
    test_data = {"user_id": 123, "role": "admin", "prefs": {"theme": "dark"}}
    serialized = serializer.serialize(test_data)
    deserialized = serializer.deserialize(serialized)
    assert deserialized == test_data, "Round-trip failed"
    print("PASS: Serialization round-trip works")

    tampered = serialized.replace("admin", "hacker")
    try:
        serializer.deserialize(tampered)
        print("FAIL: Should have detected tampering")
    except ValueError:
        print("PASS: Tampering detected")

    print("All pickle deserialization tests passed!")