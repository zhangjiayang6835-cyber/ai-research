"""
Unit tests for secure AES-GCM user data encryption.
Verifies no ECB usage, random nonce generation, pattern hiding, and AEAD tampering protection.
"""

import pytest
import os
from src.crypto import encrypt_user_data, decrypt_user_data


def test_encryption_roundtrip():
    key = os.urandom(32)
    plaintext = b"role=admin;user=alice"
    ciphertext = encrypt_user_data(key, plaintext)
    
    assert ciphertext != plaintext
    
    decrypted = decrypt_user_data(key, ciphertext)
    assert decrypted == plaintext


def test_random_nonce_pattern_hiding():
    """Verify that identical plaintexts produce different ciphertexts (random nonces / no ECB pattern leak)."""
    key = os.urandom(32)
    plaintext = b"admin" * 10
    
    ct1 = encrypt_user_data(key, plaintext)
    ct2 = encrypt_user_data(key, plaintext)
    
    assert ct1 != ct2
    assert ct1[:12] != ct2[:12]
    
    assert decrypt_user_data(key, ct1) == plaintext
    assert decrypt_user_data(key, ct2) == plaintext


def test_tamper_detection():
    """Verify that modifying ciphertext triggers authentication failure (AEAD)."""
    key = os.urandom(32)
    plaintext = b"role=user"
    ciphertext = bytearray(encrypt_user_data(key, plaintext))
    
    ciphertext[-1] ^= 0x01
    
    with pytest.raises(Exception):
        decrypt_user_data(key, bytes(ciphertext))
