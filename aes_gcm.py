"""
Secure Encryption Module - Replaces Insecure ECB Mode

This module provides AES-256-GCM authenticated encryption to replace
insecure ECB mode that leaks data patterns through identical ciphertext blocks.

Security Improvements:
- Uses AES-256-GCM (AEAD) instead of ECB
- Generates random IV for each encryption operation
- Includes authentication tag to prevent tampering
- No deterministic encryption like ECB

Reference: CVE-2019-5413, NIST SP 800-38D
"""

import os
import base64
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def encrypt(plaintext: bytes, key: bytes) -> str:
    """
    Encrypt plaintext using AES-256-GCM with random IV.
    
    Args:
        plaintext: Raw bytes to encrypt
        key: 32-byte encryption key
    
    Returns:
        Base64-encoded string containing IV + ciphertext + auth tag
    
    Raises:
        ValueError: If key is not exactly 32 bytes
    """
    if len(key) != 32:
        raise ValueError("Key must be exactly 32 bytes for AES-256")
    
    aesgcm = AESGCM(key)
    iv = os.urandom(12)  # 96-bit IV recommended for GCM
    ciphertext = aesgcm.encrypt(iv, plaintext, None)
    
    # Format: IV (12 bytes) + ciphertext+tag
    return base64.b64encode(iv + ciphertext).decode('utf-8')


def decrypt(ciphertext_b64: str, key: bytes) -> bytes:
    """
    Decrypt AES-256-GCM encrypted data.
    
    Args:
        ciphertext_b64: Base64-encoded IV + ciphertext + auth tag
        key: 32-byte encryption key
    
    Returns:
        Decrypted plaintext bytes
    
    Raises:
        ValueError: If key is invalid or decryption fails (tampering detected)
    """
    if len(key) != 32:
        raise ValueError("Key must be exactly 32 bytes for AES-256")
    
    raw = base64.b64decode(ciphertext_b64)
    iv = raw[:12]
    ciphertext = raw[12:]
    
    aesgcm = AESGCM(key)
    try:
        return aesgcm.decrypt(iv, ciphertext, None)
    except Exception as e:
        raise ValueError(f"Decryption failed - possible tampering: {e}")


def generate_key() -> str:
    """Generate a random 32-byte key and return as base64."""
    return base64.b64encode(os.urandom(32)).decode('utf-8')


if __name__ == "__main__":
    # Demo usage
    key_b64 = generate_key()
    key = base64.b64decode(key_b64)
    
    plaintext = b"admin:role=user"
    print(f"Original: {plaintext}")
    
    encrypted = encrypt(plaintext, key)
    print(f"Encrypted: {encrypted}")
    
    decrypted = decrypt(encrypted, key)
    print(f"Decrypted: {decrypted}")
    
    assert plaintext == decrypted
    print("\n✅ Encryption/decryption successful")
