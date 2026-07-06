#!/usr/bin/env python3
"""
Secure session cookie encryption using AES-GCM (authenticated encryption).
This prevents padding oracle attacks by ensuring integrity and authenticity.
"""
import os
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

def encrypt_cookie(data: bytes, key: bytes) -> str:
    """
    Encrypt and authenticate data using AES-256-GCM.
    Returns base64-encoded nonce + ciphertext + tag.
    """
    if len(key) != 32:  # AES-256 requires 32-byte key
        raise ValueError("Key must be 32 bytes")
    nonce = os.urandom(12)  # 96-bit nonce for GCM
    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(data) + encryptor.finalize()
    # Return combined: nonce + ciphertext + tag
    combined = nonce + ciphertext + encryptor.tag
    return base64.b64encode(combined).decode('utf-8')

def decrypt_cookie(encrypted: str, key: bytes) -> bytes:
    """
    Decrypt and verify authentication.
    Raises exception if tampered.
    """
    if len(key) != 32:
        raise ValueError("Key must be 32 bytes")
    combined = base64.b64decode(encrypted)
    if len(combined) < 28:  # nonce(12) + tag(16) minimum
        raise ValueError("Invalid ciphertext")
    nonce = combined[:12]
    tag = combined[-16:]
    ciphertext = combined[12:-16]
    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag), backend=default_backend())
    decryptor = cipher.decryptor()
    try:
        return decryptor.update(ciphertext) + decryptor.finalize()
    except Exception:
        # In production, log error and do not reveal padding info
        raise ValueError("Decryption failed: cookie may be tampered")

# Example usage (for testing) - do not hardcode keys in production
if __name__ == '__main__':
    key = os.urandom(32)
    cookie_data = b'{"user":"admin","role":"user"}'
    enc = encrypt_cookie(cookie_data, key)
    print("Encrypted cookie:", enc)
    dec = decrypt_cookie(enc, key)
    print("Decrypted:", dec.decode('utf-8'))
    # Attempt tampering (should fail)
    try:
        tampered = enc[:-1] + ('A' if enc[-1] != 'A' else 'B')
        decrypt_cookie(tampered, key)
    except ValueError as e:
        print("Tampered cookie detected:", e)
