"""Tests for Bleichenbacher Oracle in RSA-OAEP Decryption fix (#1337)."""

from __future__ import annotations

import os
import unittest

from fixes.bleichenbacher_oracle_1337_fix import (
    RSAKey,
    SecureOAEPDecryptor,
    constant_time_equals,
    _xor_constant_time_equals,
    _oaep_encode,
    _oaep_decode,
)


class TestBleichenbacherOracle1337(unittest.TestCase):
    """Test suite for issue #1337 fix."""

    @classmethod
    def setUpClass(cls):
        # Generate a small RSA key for testing (not production-strength)
        # Using well-known test parameters
        cls.test_n = 0x00c6d3b7c9a3f8e5b2a1d4f709e8c6d3b7c9a3f8e5b2a1d4f709e8c6d3b7c9a3f8e5b2a1d4f709e8c6d3b7c9a3f8e5b2a1d4f709e8c6d3b7c9a3f8e5b2a1d4f709e8c6d3b7c9a3f8e5b2a1d4f709e8c6d3b7c9a3f8e5b2a1d4f709e8c6d3b7c9a3f8e5b2a1d4f709e8c6d3b7c9a3f8e5b2a1d4f709e8c6d3b7c9a3f8e5b2a1d4f709e8c6d3b7c9a3f8e5b2a1d4f709e8c6d3b7c9a3f8e5b2a1d4f709e8c6d3b7
        cls.test_e = 65537
        cls.test_d = 0xd3b7c9a3f8e5b2a1d4f709e8c6d3b7c9a3f8e5b2a1d4f709e8c6d3b7c9a3f8e5b2a1d4f709e8c6d3b7c9a3f8e5b2a1d4f709e8c6d3b7c9a3f8e5b2a1d4f709e8c6d3b7c9a3f8e5b2a1d4f709e8c6d3b7c9a3f8e5b2a1d4f709e8c6d3b7c9a3f8e5b2a1d4f709e8c6d3b7c9a3f8e5b2a1d4f709e8c6d3b7c9a3f8e5b2a1d4f709e8c6d3b7c9a3f8e5b2a1d4f709e8c6d3b7c9a3f8e5b2a1d4f709e8c6d3b7c9a3f8e5b2a1d4f709e8c6d3b7c9a3f8e5b2a1d4f709e8c6d3b7c9a3f8e5b2a1d4f709e8c6d3b7c9a3f8e5b2a1
        cls.key = RSAKey(cls.test_n, cls.test_e, cls.test_d)

    def setUp(self):
        self.decryptor = SecureOAEPDecryptor(self.key)

    # ── Constant-Time Utilities ─────────────────────────────────────

    def test_constant_time_equals_matches(self) -> None:
        self.assertTrue(constant_time_equals(b"abc", b"abc"))

    def test_constant_time_equals_differs(self) -> None:
        self.assertFalse(constant_time_equals(b"abc", b"abd"))

    def test_constant_time_equals_diff_length(self) -> None:
        self.assertFalse(constant_time_equals(b"abc", b"abcd"))

    def test_xor_constant_time_equals_matches(self) -> None:
        self.assertTrue(_xor_constant_time_equals(b"abc", b"abc"))

    def test_xor_constant_time_equals_differs(self) -> None:
        self.assertFalse(_xor_constant_time_equals(b"abc", b"abd"))

    # ── OAEP Encode / Decode (round-trip) ───────────────────────────

    def test_oaep_roundtrip(self) -> None:
        """OAEP encode then decode returns original message."""
        plaintext = b"Hello, OAEP!"
        key_bytes = self.key.key_size
        encoded = _oaep_encode(plaintext, key_bytes=key_bytes)
        decoded = _oaep_decode(encoded, key_bytes=key_bytes)
        self.assertEqual(decoded, plaintext)

    def test_oaep_decode_rejects_tampered_ciphertext(self) -> None:
        """OAEP decode with tampered input returns None (no oracle)."""
        plaintext = b"Test message"
        key_bytes = self.key.key_size
        encoded = bytearray(_oaep_encode(plaintext, key_bytes=key_bytes))
        # Tamper with a byte
        encoded[len(encoded) // 2] ^= 0xff
        result = _oaep_decode(bytes(encoded), key_bytes=key_bytes)
        self.assertIsNone(result)

    # ── SecureOAEPDecryptor ─────────────────────────────────────────

    def test_valid_ciphertext_decrypts_successfully(self) -> None:
        """Valid ciphertext produces correct plaintext."""
        plaintext = b"Sensitive message"
        ct = self.decryptor.encrypt(plaintext)
        result = self.decryptor.decrypt(ct)
        self.assertEqual(result, plaintext)

    def test_invalid_ciphertext_returns_none(self) -> None:
        """Invalid ciphertext returns None (not an exception)."""
        result = self.decryptor.decrypt(b"\x00" * self.key.key_size)
        self.assertIsNone(result)

    def test_tampered_ciphertext_returns_none(self) -> None:
        """Tampered ciphertext returns None (unified error)."""
        plaintext = b"Test message"
        ct = bytearray(self.decryptor.encrypt(plaintext))
        ct[5] ^= 0x42  # Tamper
        result = self.decryptor.decrypt(bytes(ct))
        self.assertIsNone(result)

    def test_random_ciphertext_returns_none(self) -> None:
        """Random data also returns None (no oracle leak)."""
        for _ in range(10):
            random_ct = os.urandom(self.key.key_size)
            result = self.decryptor.decrypt(random_ct)
            self.assertIsNone(result)

    def test_all_failure_modes_return_same_error_type(self) -> None:
        """All failure modes produce None (no distinguishable oracle)."""
        failures = [
            b"\x00" * self.key.key_size,                 # All zeros
            b"\xff" * self.key.key_size,                 # All 0xff
            b"\x01" + b"\x00" * (self.key.key_size - 1), # Minimal
            os.urandom(self.key.key_size),                # Random
        ]
        for ct in failures:
            result = self.decryptor.decrypt(ct)
            self.assertIsNone(result)

    def test_empty_plaintext_roundtrip(self) -> None:
        """Encrypting then decrypting empty bytestring works."""
        pt = b""
        ct = self.decryptor.encrypt(pt)
        result = self.decryptor.decrypt(ct)
        self.assertEqual(result, pt)


if __name__ == "__main__":
    unittest.main()
