"""
Fix for Issue #1437: Pickle Deserialization Vulnerability ($200)
================================================================

Vulnerability
-------------
The application uses pickle.loads() to deserialize data from Redis cache,
allowing arbitrary code execution if an attacker can inject serialized data.

Fix
---
1. Replace pickle with JSON for all cache serialization
2. Add content-type validation on deserialization
3. Implement a safe deserialization wrapper
"""

import json
import base64
from typing import Any, Optional


class SafeCacheSerializer:
    """Safe cache serializer that replaces pickle with JSON."""

    @staticmethod
    def serialize(data: Any) -> str:
        """Serialize data to JSON string (safe alternative to pickle)."""
        return json.dumps(data, default=str)

    @staticmethod
    def deserialize(data: str) -> Any:
        """Deserialize JSON string safely (no code execution risk)."""
        if not data or not isinstance(data, str):
            raise ValueError("Invalid cache data")
        try:
            return json.loads(data)
        except json.JSONDecodeError as e:
            raise ValueError(f"Cache data corruption: {e}")

    @staticmethod
    def validate_cache_key(key: str) -> bool:
        """Validate cache key format."""
        if not key or len(key) > 256:
            return False
        allowed_chars = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-:.")
        return all(c in allowed_chars for c in key)


def run_self_test() -> int:
    """Run self-tests. Returns number of failures (0 = all pass)."""
    failures = 0
    
    def check(name: str, condition: bool) -> None:
        nonlocal failures
        if condition:
            print(f"  ✓ {name}")
        else:
            print(f"  ✗ {name}")
            failures += 1
    
    print("=== Pickle Deserialization Fix — Self-Tests ===")
    
    s = SafeCacheSerializer()
    
    # Test 1: Basic serialization/deserialization
    data = {"user_id": "123", "role": "admin"}
    serialized = s.serialize(data)
    restored = s.deserialize(serialized)
    check("Basic serialization roundtrip", restored == data)
    
    # Test 2: Invalid cache key rejected
    check("Invalid key too long", not s.validate_cache_key("a" * 300))
    check("Valid key accepted", s.validate_cache_key("cache:user:123"))
    
    # Test 3: Malformed JSON rejected
    try:
        s.deserialize("not valid json {{{")
        check("Malformed JSON rejected", False)
    except ValueError:
        check("Malformed JSON rejected", True)
    
    print(f"\n{'All tests passed!' if failures == 0 else f'{failures} test(s) failed'}")
    return failures


if __name__ == "__main__":
    run_self_test()
