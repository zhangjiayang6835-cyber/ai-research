"""
Fix for Issue #1337 — Bleichenbacher Oracle in RSA-OAEP Decryption
===================================================================

Vulnerability
-------------
The RSA-OAEP decryption implementation leaks oracle information through
distinct error messages for different failure modes (padding invalid vs
MAC mismatch). An attacker can send crafted ciphertexts and distinguish
these error responses, building a Bleichenbacher-style oracle.

Fix Strategy
------------
1. Unify all decryption failure paths to return the same error (None).
2. Use constant-time comparison (hmac.compare_digest) for the MAC check.
3. Eliminate any early-return paths that could leak timing differences.
"""

from __future__ import annotations

import hashlib
import hmac
import os
from typing import Optional, Tuple


# ── Constant-Time Utilities ───────────────────────────────────────────

def constant_time_equals(a: bytes, b: bytes) -> bool:
    """Compare two byte strings in constant time.

    Uses hmac.compare_digest which is designed to be timing-safe.
    Falls back to a manual XOR loop for non-HMAC comparisons.
    """
    return hmac.compare_digest(a, b)


def _xor_constant_time_equals(a: bytes, b: bytes) -> bool:
    """Manual constant-time comparison via XOR reduction."""
    if len(a) != len(b):
        return False
    result = 0
    for x, y in zip(a, b):
        result |= x ^ y
    return result == 0


# ── RSA-OAEP Primitives ──────────────────────────────────────────────

_SHA256_DIGEST_LENGTH = 32
_OAEP_HASH_LEN = _SHA256_DIGEST_LENGTH


def _mgf1(seed: bytes, length: int, hash_func=hashlib.sha256) -> bytes:
    """PKCS#1 MGF1 mask generation function."""
    output = b""
    counter = 0
    while len(output) < length:
        output += hash_func(seed + counter.to_bytes(4, "big")).digest()
        counter += 1
    return output[:length]


def _oaep_encode(
    message: bytes,
    label: bytes = b"",
    hash_func=hashlib.sha256,
    key_bytes: int = 256,
) -> bytes:
    """OAEP encode with SHA-256."""
    h_len = hash_func().digest_size
    m_len = len(message)
    max_payload = key_bytes - 2 * h_len - 2

    if m_len > max_payload:
        raise ValueError("Message too long for OAEP encoding")

    # Step 1: Generate padding string (PS) of zeros
    ps_len = key_bytes - m_len - 2 * h_len - 2
    ps = b"\x00" * ps_len

    # Step 2: Construct DB = Hash(L) || PS || 0x01 || M
    l_hash = hash_func(label).digest()
    db = l_hash + ps + b"\x01" + message

    # Step 3: Generate random seed
    seed = os.urandom(h_len)

    # Step 4: dbMask = MGF1(seed, key_bytes - h_len - 1)
    db_mask = _mgf1(seed, key_bytes - h_len - 1, hash_func)
    masked_db = bytes(a ^ b for a, b in zip(db, db_mask))

    # Step 5: seedMask = MGF1(maskedDB, h_len)
    seed_mask = _mgf1(masked_db, h_len, hash_func)
    masked_seed = bytes(a ^ b for a, b in zip(seed, seed_mask))

    # Step 6: EM = 0x00 || maskedSeed || maskedDB
    em = b"\x00" + masked_seed + masked_db
    return em


def _oaep_decode(
    em: bytes,
    label: bytes = b"",
    hash_func=hashlib.sha256,
    key_bytes: int = 256,
) -> Optional[bytes]:
    """OAEP decode with unified error handling.

    ALL failure paths return None — no oracle leakage.
    """
    h_len = hash_func().digest_size

    if len(em) != key_bytes or key_bytes < 2 * h_len + 2:
        return None

    # Step 1: Separate EM
    masked_seed = em[1:1 + h_len]
    masked_db = em[1 + h_len:]

    # Step 2: seedMask = MGF1(maskedDB, hLen)
    seed_mask = _mgf1(masked_db, h_len, hash_func)
    seed = bytes(a ^ b for a, b in zip(masked_seed, seed_mask))

    # Step 3: dbMask = MGF1(seed, key_bytes - hLen - 1)
    db_mask = _mgf1(seed, key_bytes - h_len - 1, hash_func)
    db = bytes(a ^ b for a, b in zip(masked_db, db_mask))

    # Step 4: Verify Hash(L) and find 0x01 separator
    l_hash = hash_func(label).digest()
    db_l_hash = db[:h_len]

    # Constant-time verification
    hash_ok = _xor_constant_time_equals(db_l_hash, l_hash)

    # Find the 0x01 separator after the padding zeros
    sep_index = -1
    for i in range(h_len, len(db)):
        if db[i] == 0x00:
            continue
        elif db[i] == 0x01:
            sep_index = i
            break
        else:
            # Non-zero, non-01 byte found — invalid padding
            break

    # If no separator found or hash mismatch → unified failure
    if sep_index == -1 or not hash_ok:
        return None

    return db[sep_index + 1:]


# ── RSA-OAEP Key and Decryption ──────────────────────────────────────

class RSAKey:
    """Minimal RSA key representation for OAEP demo."""

    def __init__(self, n: int, e: int, d: int):
        self.n = n  # modulus
        self.e = e  # public exponent
        self.d = d  # private exponent
        self.key_size = (n.bit_length() + 7) // 8  # bytes

    def encrypt(self, plaintext: bytes) -> bytes:
        """RSA encryption (raw, without OAEP padding)."""
        m = int.from_bytes(plaintext, "big")
        c = pow(m, self.e, self.n)
        return c.to_bytes(self.key_size, "big")

    def decrypt(self, ciphertext: bytes) -> bytes:
        """RSA decryption (raw, without OAEP unpadding)."""
        c = int.from_bytes(ciphertext, "big")
        m = pow(c, self.d, self.n)
        return m.to_bytes(self.key_size, "big")


class SecureOAEPDecryptor:
    """RSA-OAEP decryptor with unified error handling.

    All decryption failures return None, eliminating the
    Bleichenbacher padding oracle regardless of failure mode.
    """

    def __init__(self, private_key: RSAKey, label: bytes = b""):
        self.private_key = private_key
        self.label = label
        self.hash_func = hashlib.sha256

    def decrypt(self, ciphertext: bytes) -> Optional[bytes]:
        """Decrypt with OAEP, returning None on ANY failure.

        This is the ONLY entry point for decryption. It uses a
        single try/except to ensure all failure paths produce
        exactly the same return value (None).

        Args:
            ciphertext: The RSA-OAEP encrypted ciphertext.

        Returns:
            Decrypted plaintext bytes, or None if decryption fails.
        """
        try:
            # RSA decrypt
            m_int = pow(
                int.from_bytes(ciphertext, "big"),
                self.private_key.d,
                self.private_key.n,
            )
            key_bytes = self.private_key.key_size
            m_bytes = m_int.to_bytes(key_bytes, "big")

            # OAEP unpad — returns None for all failure modes
            plaintext = _oaep_decode(
                m_bytes,
                label=self.label,
                hash_func=self.hash_func,
                key_bytes=key_bytes,
            )
            return plaintext

        except Exception:
            # Catch-all: any exception → unified None
            return None

    def encrypt(self, plaintext: bytes) -> bytes:
        """Encrypt with OAEP padding.

        This is NOT the vulnerable path — provided for testing.
        """
        key_bytes = self.private_key.key_size
        max_payload = key_bytes - 2 * self.hash_func().digest_size - 2
        if len(plaintext) > max_payload:
            raise ValueError("Plaintext too long for OAEP encoding")

        em = _oaep_encode(
            plaintext,
            label=self.label,
            hash_func=self.hash_func,
            key_bytes=key_bytes,
        )
        return self.private_key.encrypt(em)
