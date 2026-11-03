"""
Secure cryptographic module using AES-256-GCM (AEAD).
Replaces insecure AES-ECB mode to prevent data leaks via pattern matching.
"""

from __future__ import annotations

import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def encrypt_user_data(key: bytes, plaintext: bytes) -> bytes:
    """
    Encrypt user data using AES-256-GCM authenticated encryption (AEAD).
    Generates a cryptographically secure random 12-byte nonce (IV).
    Returns nonce + ciphertext + auth tag.
    """
    if not isinstance(key, bytes) or not isinstance(plaintext, bytes):
        raise TypeError("Key and plaintext must be bytes")
    
    if len(key) != 32:
        if len(key) < 32:
            key = key.ljust(32, b'\0')
        else:
            key = key[:32]
            
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)  # 96-bit random nonce / IV
    return nonce + aesgcm.encrypt(nonce, plaintext, None)


def decrypt_user_data(key: bytes, ciphertext: bytes) -> bytes:
    """
    Decrypt user data using AES-256-GCM authenticated encryption (AEAD).
    Expects nonce (12 bytes) + ciphertext (with auth tag).
    """
    if not isinstance(key, bytes) or not isinstance(ciphertext, bytes):
        raise TypeError("Key and ciphertext must be bytes")
        
    if len(key) != 32:
        if len(key) < 32:
            key = key.ljust(32, b'\0')
        else:
            key = key[:32]
            
    if len(ciphertext) < 28:
        raise ValueError("Ciphertext too short")
        
    nonce = ciphertext[:12]
    ct = ciphertext[12:]
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ct, None)


encrypt = encrypt_user_data
decrypt = decrypt_user_data
encrypt_aes_gcm = encrypt_user_data
decrypt_aes_gcm = decrypt_user_data
