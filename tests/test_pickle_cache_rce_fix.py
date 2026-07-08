"""
Regression tests for Issue #659: Pickle Deserialization RCE via Cache.

These tests verify that:
  - SafeCacheSerializer round-trips values without pickle.
  - Tampered cache values are rejected (signature verification).
  - Cross-key verification fails.
  - TTL expiration is enforced.
  - Malformed envelopes are rejected.
  - Module-level convenience functions work after configuration.
"""

from __future__ import annotations

import json
import os
import time

import pytest

from fixes.pickle_cache_rce_fix import (
    CacheSecurityError,
    SafeCacheSerializer,
    configure,
    safe_cache_dumps,
    safe_cache_loads,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def serializer() -> SafeCacheSerializer:
    """Fresh serializer with a random key for each test."""
    return SafeCacheSerializer(secret_key=os.urandom(32))


@pytest.fixture
def sample_session() -> dict:
    """A realistic-looking user session."""
    return {
        "user_id": "usr_abc123",
        "username": "alice",
        "role": "admin",
        "permissions": ["read", "write", "delete"],
        "last_login": 1718400000,
    }


# ---------------------------------------------------------------------------
# Round-trip tests
# ---------------------------------------------------------------------------


class TestRoundTrip:
    """Values must survive a dumps → loads cycle unchanged."""

    def test_session_dict_roundtrip(self, serializer, sample_session):
        data = serializer.dumps(sample_session)
        result = serializer.loads(data)
        assert result == sample_session

    @pytest.mark.parametrize(
        "value",
        [
            "hello world",
            42,
            3.14,
            True,
            False,
            None,
            [1, "two", 3.0],
            {"nested": {"deep": [1, 2, 3]}},
            [],
            {},
        ],
    )
    def test_primitive_roundtrip(self, serializer, value):
        assert serializer.loads(serializer.dumps(value)) == value

    def test_unicode_roundtrip(self, serializer):
        obj = {"name": "Jöhn Dœ", "city": "München", "emoji": "🚀"}
        assert serializer.loads(serializer.dumps(obj)) == obj


# ---------------------------------------------------------------------------
# Anti-tampering tests
# ---------------------------------------------------------------------------


class TestTamperDetection:
    """Any modification of the signed envelope must be detected."""

    def test_modified_payload_rejected(self, serializer, sample_session):
        data = bytearray(serializer.dumps(sample_session))
        # Flip a bit in the middle
        data[len(data) // 2] ^= 0x01
        with pytest.raises(CacheSecurityError, match="signature"):
            serializer.loads(bytes(data))

    def test_truncated_data_rejected(self, serializer, sample_session):
        data = serializer.dumps(sample_session)
        with pytest.raises(
            CacheSecurityError,
        ):
            serializer.loads(data[:10])

    def test_empty_bytes_rejected(self, serializer):
        with pytest.raises(CacheSecurityError):
            serializer.loads(b"")

    def test_appended_data_rejected(self, serializer, sample_session):
        data = serializer.dumps(sample_session) + b"extra"
        with pytest.raises(CacheSecurityError, match="signature"):
            serializer.loads(data)

    def test_different_key_cannot_verify(self, serializer, sample_session):
        data = serializer.dumps(sample_session)
        other = SafeCacheSerializer(secret_key=os.urandom(32))
        with pytest.raises(CacheSecurityError, match="signature"):
            other.loads(data)

    def test_tampered_signature_rejected(self, serializer, sample_session):
        data = serializer.dumps(sample_session)
        envelope = json.loads(data.decode("utf-8"))
        # Flip a character in the signature
        envelope["sig"] = envelope["sig"][:-1] + (
            "a" if envelope["sig"][-1] != "a" else "b"
        )
        tampered = json.dumps(envelope, separators=(",", ":")).encode()
        with pytest.raises(CacheSecurityError, match="signature"):
            serializer.loads(tampered)


# ---------------------------------------------------------------------------
# TTL tests
# ---------------------------------------------------------------------------


class TestTTL:
    """Values older than the configured TTL must be rejected."""

    def test_ttl_expired_rejected(self, sample_session):
        serializer = SafeCacheSerializer(
            secret_key=os.urandom(32), ttl_seconds=0
        )
        data = serializer.dumps(sample_session)
        time.sleep(1.1)  # ensure expiry
        with pytest.raises(CacheSecurityError, match="expired"):
            serializer.loads(data)

    def test_ttl_within_window_accepted(self, sample_session):
        serializer = SafeCacheSerializer(
            secret_key=os.urandom(32), ttl_seconds=3600
        )
        data = serializer.dumps(sample_session)
        result = serializer.loads(data)
        assert result == sample_session

    def test_no_ttl_accepts_any_age(self, serializer, sample_session):
        """Without TTL, values of any age should be accepted."""
        data = serializer.dumps(sample_session)
        result = serializer.loads(data)
        assert result == sample_session


# ---------------------------------------------------------------------------
# Malformed input tests
# ---------------------------------------------------------------------------


class TestMalformedInput:
    """Garbage input must raise CacheSecurityError, never crash."""

    def test_not_bytes_raises(self, serializer):
        with pytest.raises(CacheSecurityError):
            serializer.loads("not bytes")  # type: ignore[arg-type]

    def test_non_json_raises(self, serializer):
        with pytest.raises(CacheSecurityError, match="not valid JSON"):
            serializer.loads(b"this is not json {{{")

    def test_json_not_object_raises(self, serializer):
        with pytest.raises(CacheSecurityError, match="object"):
            serializer.loads(b"[1, 2, 3]")

    def test_missing_fields_raises(self, serializer):
        bad = json.dumps({"v": "payload"}).encode()  # missing t and sig
        with pytest.raises(CacheSecurityError, match="missing"):
            serializer.loads(bad)

    def test_null_payload_rejected(self, serializer):
        bad = json.dumps(
            {"v": None, "t": 1234567890, "sig": "abcdef"}
        ).encode()
        with pytest.raises(CacheSecurityError, match="invalid"):
            serializer.loads(bad)


# ---------------------------------------------------------------------------
# Module-level convenience functions
# ---------------------------------------------------------------------------


class TestModuleLevelAPI:
    """configure() / safe_cache_dumps() / safe_cache_loads() integration."""

    def test_configure_and_use(self):
        configure(secret_key=os.urandom(32))
        obj = {"test": "module-level"}
        data = safe_cache_dumps(obj)
        result = safe_cache_loads(data)
        assert result == obj

    def test_not_configured_raises(self):
        # Force unconfigured state by re-importing the module-level var
        import fixes.pickle_cache_rce_fix as mod

        mod._default_serializer = None
        with pytest.raises(RuntimeError, match="not configured"):
            mod.safe_cache_dumps({"x": 1})
        with pytest.raises(RuntimeError, match="not configured"):
            mod.safe_cache_loads(b"{}")


# ---------------------------------------------------------------------------
# Key validation
# ---------------------------------------------------------------------------


class TestKeyValidation:
    """Secret key must meet minimum length requirements."""

    def test_short_key_raises(self):
        with pytest.raises(ValueError, match="at least 32 bytes"):
            SafeCacheSerializer(secret_key="short")

    def test_exact_32_byte_key_accepted(self):
        serializer = SafeCacheSerializer(secret_key=b"x" * 32)
        data = serializer.dumps({"ok": True})
        assert serializer.loads(data) == {"ok": True}

    def test_string_key_accepted(self):
        serializer = SafeCacheSerializer(secret_key="a" * 32)
        data = serializer.dumps({"ok": True})
        assert serializer.loads(data) == {"ok": True}
