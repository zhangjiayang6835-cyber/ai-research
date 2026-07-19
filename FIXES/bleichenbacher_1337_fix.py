"""
Fix for Issue #1337 — Bleichenbacher Oracle in RSA-OAEP Decryption
===================================================================

Vulnerability: RSA-OAEP decryption leaks oracle info through distinct
error messages for padding vs MAC failures.

Fix: Unified error response (None) for ALL decryption failures,
constant-time comparison for MAC check.
"""

from __future__ import annotations

import hashlib
import hmac
import os
from typing import Optional


def constant_time_equals(a: bytes, b: bytes) -> bool:
    return hmac.compare_digest(a, b)


def _xor_ct_eq(a: bytes, b: bytes) -> bool:
    if len(a) != len(b):
        return False
    result = 0
    for x, y in zip(a, b):
        result |= x ^ y
    return result == 0


def _mgf1(seed: bytes, length: int, hash_func=hashlib.sha256) -> bytes:
    output = b""
    counter = 0
    while len(output) < length:
        output += hash_func(seed + counter.to_bytes(4, "big")).digest()
        counter += 1
    return output[:length]


def _oaep_encode(
    message: bytes, label: bytes = b"",
    hash_func=hashlib.sha256, key_bytes: int = 256,
) -> bytes:
    h_len = hash_func().digest_size
    m_len = len(message)
    max_payload = key_bytes - 2 * h_len - 2
    if m_len > max_payload:
        raise ValueError("Message too long")
    ps_len = key_bytes - m_len - 2 * h_len - 2
    ps = b"\x00" * ps_len
    l_hash = hash_func(label).digest()
    db = l_hash + ps + b"\x01" + message
    seed = os.urandom(h_len)
    db_mask = _mgf1(seed, key_bytes - h_len - 1, hash_func)
    masked_db = bytes(a ^ b for a, b in zip(db, db_mask))
    seed_mask = _mgf1(masked_db, h_len, hash_func)
    masked_seed = bytes(a ^ b for a, b in zip(seed, seed_mask))
    return b"\x00" + masked_seed + masked_db


def _oaep_decode(
    em: bytes, label: bytes = b"",
    hash_func=hashlib.sha256, key_bytes: int = 256,
) -> Optional[bytes]:
    h_len = hash_func().digest_size
    if len(em) != key_bytes or key_bytes < 2 * h_len + 2:
        return None
    masked_seed = em[1:1 + h_len]
    masked_db = em[1 + h_len:]
    seed_mask = _mgf1(masked_db, h_len, hash_func)
    seed = bytes(a ^ b for a, b in zip(masked_seed, seed_mask))
    db_mask = _mgf1(seed, key_bytes - h_len - 1, hash_func)
    db = bytes(a ^ b for a, b in zip(masked_db, db_mask))
    l_hash = hash_func(label).digest()
    db_l_hash = db[:h_len]
    hash_ok = _xor_ct_eq(db_l_hash, l_hash)
    sep_index = -1
    for i in range(h_len, len(db)):
        if db[i] == 0x00:
            continue
        elif db[i] == 0x01:
            sep_index = i
            break
        else:
            break
    if sep_index == -1 or not hash_ok:
        return None
    return db[sep_index + 1:]


class RSAKey:
    def __init__(self, n: int, e: int, d: int):
        self.n = n
        self.e = e
        self.d = d
        self.key_size = (n.bit_length() + 7) // 8

    def encrypt(self, pt: bytes) -> bytes:
        m = int.from_bytes(pt, "big")
        c = pow(m, self.e, self.n)
        return c.to_bytes(self.key_size, "big")

    def decrypt(self, ct: bytes) -> bytes:
        c = int.from_bytes(ct, "big")
        m = pow(c, self.d, self.n)
        return m.to_bytes(self.key_size, "big")


class SecureOAEPDecryptor:
    """RSA-OAEP decryptor with unified error handling.

    ALL decryption failures return None — no oracle leakage.
    """

    def __init__(self, private_key: RSAKey, label: bytes = b""):
        self.private_key = private_key
        self.label = label
        self.hash_func = hashlib.sha256

    def decrypt(self, ciphertext: bytes) -> Optional[bytes]:
        try:
            m_int = pow(
                int.from_bytes(ciphertext, "big"),
                self.private_key.d, self.private_key.n,
            )
            key_bytes = self.private_key.key_size
            m_bytes = m_int.to_bytes(key_bytes, "big")
            return _oaep_decode(
                m_bytes, label=self.label,
                hash_func=self.hash_func, key_bytes=key_bytes,
            )
        except Exception:
            return None

    def encrypt(self, plaintext: bytes) -> bytes:
        key_bytes = self.private_key.key_size
        max_payload = key_bytes - 2 * self.hash_func().digest_size - 2
        if len(plaintext) > max_payload:
            raise ValueError("Plaintext too long")
        em = _oaep_encode(
            plaintext, label=self.label,
            hash_func=self.hash_func, key_bytes=key_bytes,
        )
        return self.private_key.encrypt(em)
