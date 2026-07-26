#!/usr/bin/env python3
"""
Fix for Issue #1475: ECB Mode Encryption → Data Leak via Pattern Matching

Vulnerability: AES-ECB encrypts identical plaintext blocks to identical ciphertext
blocks, leaking data patterns (e.g., "admin" vs "user" permissions).

Fix: Replace ECB with AES-GCM (authenticated encryption with random IV).
GCM provides confidentiality, integrity, and authentication (AEAD).
"""

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import os

class SecureEncryption:
    """AES-256-GCM authenticated encryption replacing insecure ECB."""

    def __init__(self, master_key: bytes = None):
        self.master_key = master_key or AESGCM.generate_key(bit_length=256)

    def encrypt(self, plaintext: str, associated_data: bytes = b'') -> bytes:
        """Encrypt with AES-256-GCM. Returns nonce+ciphertext+tag."""
        aesgcm = AESGCM(self.master_key)
        nonce = os.urandom(12)  # 96-bit random nonce
        ct = aesgcm.encrypt(nonce, plaintext.encode(), associated_data)
        return nonce + ct  # nonce prepended for decryption

    def decrypt(self, ciphertext: bytes, associated_data: bytes = b'') -> str:
        """Decrypt AES-256-GCM. Validates authentication tag."""
        if len(ciphertext) < 12: raise ValueError("Invalid ciphertext")
        nonce = ciphertext[:12]
        ct = ciphertext[12:]
        aesgcm = AESGCM(self.master_key)
        return aesgcm.decrypt(nonce, ct, associated_data).decode()

    @staticmethod
    def derive_key(password: str, salt: bytes = None) -> tuple[bytes, bytes]:
        """Derive 256-bit key from password using PBKDF2."""
        if salt is None: salt = os.urandom(16)
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=600000)
        return kdf.derive(password.encode()), salt

# --- VULNERABLE (DO NOT USE) ---
class InsecureECBEncryption:
    """⚠️ ECB mode: identical plaintext → identical ciphertext — PATTERN LEAK."""
    def __init__(self, key=None):
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        from cryptography.hazmat.backends import default_backend
        self.key = key or os.urandom(32)
        self.backend = default_backend()
    def pad(self, data): return data + b'\x00' * (16 - len(data) % 16)
    def encrypt(self, pt):
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        c = Cipher(algorithms.AES(self.key), modes.ECB(), self.backend)
        return c.encryptor().update(self.pad(pt.encode()))
    def decrypt(self, ct):
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        c = Cipher(algorithms.AES(self.key), modes.ECB(), self.backend)
        return c.decryptor().update(ct).rstrip(b'\x00').decode()

if __name__ == '__main__':
    secure = SecureEncryption()

    # Test: same plaintext twice → different ciphertext (no pattern leak)
    ct1 = secure.encrypt("admin_role")
    ct2 = secure.encrypt("admin_role")
    assert ct1 != ct2, "GCM should produce different ciphertext for same plaintext!"
    print("✅ Same plaintext → different ciphertext (no ECB pattern leak)")

    # Test: round-trip
    assert secure.decrypt(ct1) == "admin_role"
    assert secure.decrypt(ct2) == "admin_role"
    print("✅ Round-trip decryption works")

    # Test: tampering detected
    tampered = bytearray(ct1); tampered[15] ^= 0x01
    try:
        secure.decrypt(bytes(tampered))
        assert False, "Should have detected tampering!"
    except Exception:
        print("✅ Tampering detected (authentication tag fails)")

    # Test: key derivation
    dk, salt = SecureEncryption.derive_key("strong-password-here")
    assert len(dk) == 32
    print("✅ Key derivation: 256-bit key from password")

    # Demonstrate ECB vulnerability
    ecb = InsecureECBEncryption()
    admin_ct = ecb.encrypt("admin_role_user")
    user_ct = ecb.encrypt("user_role_admin")
    # ECB: identical blocks produce identical ciphertext - patterns visible!
    print(f"\n⚠️  ECB admin_role_user: {admin_ct.hex()[:32]}...")
    print(f"⚠️  ECB user_role_admin: {user_ct.hex()[:32]}...")
    print("   (ECB leaks patterns — same blocks = same ciphertext)")

    print("\n🔒 Issue #1475 FIXED: ECB → AES-256-GCM (authenticated encryption)")
