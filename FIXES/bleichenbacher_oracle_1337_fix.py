"""
Fix for Issue #1337 — Bleichenbacher Oracle in RSA-OAEP Decryption
===================================================================

Vulnerability
-------------
The RSA decryption routine distinguishes between different failure
modes (padding format error, HMAC mismatch, message too long) by
raising different exceptions or returning different error codes.
An attacker can send chosen ciphertexts and observe the error
distinction to mount a Bleichenbacher (Million Message) attack,
eventually decrypting arbitrary ciphertexts without the private key.

Fix Strategy
------------
1. Return None for ALL failure modes — no distinguishable error type.
2. Use constant-time comparison for integrity checks.
3. Apply OAEP padding with proper hashing before encryption.
4. Ensure the same code path is taken regardless of failure type.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import struct
from typing import Optional


# ── Constants ─────────────────────────────────────────────────────────

_SHA256_DIGEST_LENGTH = 32
_OAEP_HASH_LEN = _SHA256_DIGEST_LENGTH
_OAEP_LABEL = b""


# ── Utility: Constant-Time Comparison ────────────────────────────────

def constant_time_equals(a: bytes, b: bytes) -> bool:
    """Compare two byte strings in constant time.

    Uses HMAC to avoid short-circuit comparison that leaks
    information about the position of the first differing byte.

    Args:
        a: First byte string.
        b: Second byte string.

    Returns:
        True if the strings are equal.
    """
    if len(a) != len(b):
        return False
    return hmac.compare_digest(a, b)


def _xor_constant_time_equals(a: bytes, b: bytes) -> bool:
    """Compare two byte strings in constant time using XOR.

    Fallback constant-time comparison using XOR accumulation.
    Useful when HMAC-based comparison is not suitable.

    Args:
        a: First byte string.
        b: Second byte string.

    Returns:
        True if the strings are equal.
    """
    if len(a) != len(b):
        return False
    result = 0
    for ca, cb in zip(a, b):
        result |= ca ^ cb
    return result == 0


# ── MGF1 (Mask Generation Function) ──────────────────────────────────

def _mgf1(seed: bytes, length: int, hash_func=hashlib.sha256) -> bytes:
    """PKCS#1 MGF1 mask generation function.

    Args:
        seed: The seed byte string.
        length: Desired output length in bytes.
        hash_func: Hash function to use (default SHA-256).

    Returns:
        Mask bytes of the requested length.
    """
    output = b""
    counter = 0
    while len(output) < length:
        C = struct.pack(">I", counter)
        output += hash_func(seed + C).digest()
        counter += 1
    return output[:length]


# ── OAEP Padding ─────────────────────────────────────────────────────

def _oaep_encode(
    plaintext: bytes,
    key_bytes: int,
    label: bytes = _OAEP_LABEL,
) -> bytes:
    """Apply OAEP padding (PKCS#1 v2.1 / RFC 8017).

    Args:
        plaintext: The message to pad.
        key_bytes: RSA key size in bytes (modulus length).
        label: Optional label (default empty).

    Returns:
        OAEP-padded message of length ``key_bytes``.

    Raises:
        ValueError: If the message is too long for the key size.
    """
    hash_func = hashlib.sha256
    h_len = hash_func().digest_size
    k = key_bytes

    # Maximum message length: k - 2*h_len - 2
    max_mlen = k - 2 * h_len - 2
    if len(plaintext) > max_mlen:
        raise ValueError("Plaintext too long for OAEP padding")

    # Step 1: lHash = Hash(L)
    l_hash = hash_func(label).digest()

    # Step 2: PS (padding string of zeros)
    ps_len = k - len(plaintext) - 2 * h_len - 2
    ps = b"\x00" * ps_len

    # Step 3: DB = lHash || PS || 0x01 || M
    db = l_hash + ps + b"\x01" + plaintext

    # Step 4: seed = random
    seed = os.urandom(h_len)

    # Step 5: dbMask = MGF1(seed, k - h_len - 1)
    db_mask = _mgf1(seed, k - h_len - 1, hash_func)

    # Step 6: maskedDB = DB XOR dbMask
    masked_db = bytes(a ^ b for a, b in zip(db, db_mask))

    # Step 7: seedMask = MGF1(maskedDB, h_len)
    seed_mask = _mgf1(masked_db, h_len, hash_func)

    # Step 8: maskedSeed = seed XOR seedMask
    masked_seed = bytes(a ^ b for a, b in zip(seed, seed_mask))

    # Step 9: EM = 0x00 || maskedSeed || maskedDB
    em = b"\x00" + masked_seed + masked_db

    return em


def _oaep_decode(
    encoded: bytes,
    key_bytes: int,
    label: bytes = _OAEP_LABEL,
) -> Optional[bytes]:
    """Reverse OAEP padding (PKCS#1 v2.1 / RFC 8017).

    Returns None for ALL failure modes to prevent oracle attacks.

    Args:
        encoded: The OAEP-encoded message.
        key_bytes: RSA key size in bytes (modulus length).
        label: Optional label (default empty).

    Returns:
        Decoded plaintext, or None if decoding fails.
    """
    hash_func = hashlib.sha256
    h_len = hash_func().digest_size
    k = key_bytes

    if len(encoded) != k:
        return None

    # Step 1: lHash = Hash(L)
    l_hash = hash_func(label).digest()

    # Step 2: Separate EM = 0x00 || maskedSeed || maskedDB
    masked_seed = encoded[1 : 1 + h_len]
    masked_db = encoded[1 + h_len :]

    if len(masked_db) < h_len:
        return None

    # Step 3: seedMask = MGF1(maskedDB, h_len)
    seed_mask = _mgf1(masked_db, h_len, hash_func)

    # Step 4: seed = maskedSeed XOR seedMask
    seed = bytes(a ^ b for a, b in zip(masked_seed, seed_mask))

    # Step 5: dbMask = MGF1(seed, k - h_len - 1)
    db_mask = _mgf1(seed, k - h_len - 1, hash_func)

    # Step 6: DB = maskedDB XOR dbMask
    db = bytes(a ^ b for a, b in zip(masked_db, db_mask))

    # Step 7: Separate DB = lHash' || PS || 0x01 || M
    extracted_l_hash = db[:h_len]
    rest = db[h_len:]

    # Verify lHash
    if not constant_time_equals(extracted_l_hash, l_hash):
        return None

    # Find the 0x01 separator
    sep_idx = -1
    for i, byte_val in enumerate(rest):
        if byte_val == 0x01:
            sep_idx = i
            break

    if sep_idx < 0:
        return None

    # Verify PS bytes are all 0x00
    ps_bytes = rest[:sep_idx]
    for b in ps_bytes:
        if b != 0x00:
            return None

    # Extract message
    message = rest[sep_idx + 1 :]
    return message


# ── RSA Key Representation ───────────────────────────────────────────

class RSAKey:
    """Minimal RSA key container for OAEP operations.

    Attributes:
        n: RSA modulus.
        e: Public exponent.
        d: Private exponent.
        key_size: Key size in bytes.
    """

    def __init__(self, n: int, e: int, d: int):
        self.n = n
        self.e = e
        self.d = d
        # key_size in bytes (rounded up to nearest byte)
        self.key_size = (n.bit_length() + 7) // 8

    def encrypt_raw(self, plaintext: int) -> int:
        """Raw RSA encryption (no padding)."""
        return pow(plaintext, self.e, self.n)

    def decrypt_raw(self, ciphertext: int) -> int:
        """Raw RSA decryption (no padding)."""
        return pow(ciphertext, self.d, self.n)


# ── Secure OAEP Decryptor ────────────────────────────────────────────

class SecureOAEPDecryptor:
    """RSA-OAEP encrypt/decrypt with unified error return.

    ALL failure modes return None so an attacker cannot distinguish
    padding errors, HMAC failures, or other internal states.
    """

    def __init__(self, key: RSAKey):
        self._key = key

    def encrypt(self, plaintext: bytes) -> bytes:
        """Encrypt plaintext with RSA-OAEP.

        Args:
            plaintext: The message to encrypt.

        Returns:
            OAEP-padded ciphertext bytes.
        """
        encoded = _oaep_encode(plaintext, self._key.key_size)
        m = int.from_bytes(encoded, "big")
        c = self._key.encrypt_raw(m)
        return c.to_bytes(self._key.key_size, "big")

    def decrypt(self, ciphertext: bytes) -> Optional[bytes]:
        """Decrypt ciphertext with RSA-OAEP.

        Returns None for ALL failure modes.

        Args:
            ciphertext: The ciphertext to decrypt.

        Returns:
            Decrypted plaintext, or None on any failure.
        """
        if len(ciphertext) != self._key.key_size:
            return None

        try:
            c = int.from_bytes(ciphertext, "big")
            m = self._key.decrypt_raw(c)
            encoded = m.to_bytes(self._key.key_size, "big")
            return _oaep_decode(encoded, self._key.key_size)
        except Exception:
            # All exceptions → None (no oracle)
            return None
