"""
Fix for Issue #1215 — Python Pickle Deserialization RCE via Cache
==================================================================

Vulnerability
-------------
Redis cache stores user sessions serialized with pickle.dumps(). Attackers
write malicious pickle payloads to the cache. When the server calls
pickle.loads(), arbitrary code execution is triggered.

Fix Strategy
------------
1. Replace pickle with JSON serialization for all cache data.
"""

import json

class SafeSessionCache:
    """Cache that uses JSON serialization to prevent deserialization attacks."""

    def __init__(self, redis_client):
        self.redis = redis_client

    def set_session(self, session_id: str, data: dict, ttl: int = 3600) -> None:
        serialized = json.dumps(data, ensure_ascii=False, default=str)
        self.redis.setex(f"session:{session_id}", ttl, serialized)

    def get_session(self, session_id: str) -> dict | None:
        data = self.redis.get(f"session:{session_id}")
        if data is None:
            return None
        return json.loads(data)

def apply_security_patch(input_data):
    """Apply security fix: JSON deserialization instead of pickle."""
    if not isinstance(input_data, bytes):
        return {"status": "error", "data": "Invalid input"}
    
    try:
        data = json.loads(input_data.decode("utf-8"))
    except Exception:
        return {"status": "error", "data": "Deserialization failed"}
        
    return {"status": "patched", "data": data}

if __name__ == "__main__":
    # Test JSON deserialization
    test_data = json.dumps({"session_id": "12345", "user": "admin"}).encode("utf-8")
    result = apply_security_patch(test_data)
    assert result["status"] == "patched", f"Failed to patch: {result}"
    assert result["data"]["user"] == "admin"
    print("✓ JSON deserialization successful")
    
    # Test invalid JSON
    result = apply_security_patch(b"invalid data")
    assert result["status"] == "error"
    print("✓ Invalid data handled safely")
    
    print("\n✅ All tests passed for #1215: Pickle Deserialization RCE via Cache Fix")
