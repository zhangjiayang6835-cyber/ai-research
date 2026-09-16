"""
ECB Mode Encryption Fix - Data Leak via Pattern Matching ($120)

Vulnerability:
- User data encrypted with AES-ECB mode
- ECB produces identical ciphertext for identical plaintext blocks
- Attackers can identify data patterns (admin vs user permission bits)
- No authentication, enabling ciphertext manipulation

Fix Strategy:
1. Replace AES-ECB with AES-GCM (AEAD - Authenticated Encryption)
2. Generate random IV per encryption operation
3. Include authentication tag to prevent tampering
4. Proper key derivation using HKDF
"""

from __future__ import annotations

import os
import base64
from dataclasses import dataclass
from typing import Optional


# =============================================================================
# AES-GCM Secure Encryption
# =============================================================================

class EncryptionError(Exception):
    pass


@dataclass
class EncryptedData:
    """Container for AES-GCM encrypted data."""
    ciphertext: bytes
    iv: bytes
    tag: bytes
    aad: Optional[bytes] = None

    def to_bytes(self) -> bytes:
        """Serialize: IV(12) + Tag(16) + Ciphertext"""
        return self.iv + self.tag + self.ciphertext

    @classmethod
    def from_bytes(cls, data: bytes) -> "EncryptedData":
        """Deserialize: IV(12) + Tag(16) + Ciphertext"""
        if len(data) < 28:
            raise EncryptionError("Data too short to be valid AES-GCM output")
        iv = data[:12]
        tag = data[12:28]
        ciphertext = data[28:]
        return cls(ciphertext=ciphertext, iv=iv, tag=tag)


class SecureAESGCM:
    """
    Secure AES-256-GCM encryption/decryption.
    
    Replaces insecure AES-ECB with AES-GCM (AEAD).
    - Random IV per encryption
    - Authentication tag prevents tampering
    - No deterministic output (same plaintext -> different ciphertext)
    """

    # IV size for AES-GCM (12 bytes recommended)
    IV_SIZE = 12
    # Tag size (16 bytes standard)
    TAG_SIZE = 16
    # Key size (32 bytes = 256 bits)
    KEY_SIZE = 32

    def __init__(self, key: Optional[bytes] = None):
        """
        Initialize with a 32-byte key.
        If no key provided, generates a random one.
        """
        try:
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
            self._AESGCM = AESGCM
        except ImportError:
            raise EncryptionError(
                "cryptography package required. Install with: pip install cryptography"
            )

        if key is None:
            self.key = os.urandom(self.KEY_SIZE)
        elif len(key) != self.KEY_SIZE:
            raise EncryptionError(
                f"Key must be {self.KEY_SIZE} bytes, got {len(key)}"
            )
        else:
            self.key = key

    def encrypt(self, plaintext: bytes, aad: Optional[bytes] = None) -> EncryptedData:
        """
        Encrypt plaintext using AES-256-GCM with random IV.
        
        Args:
            plaintext: Data to encrypt
            aad: Optional additional authenticated data
        
        Returns:
            EncryptedData with IV, tag, and ciphertext
        """
        aesgcm = self._AESGCM(self.key)
        iv = os.urandom(self.IV_SIZE)
        
        # AES-GCM encrypt_and_tag returns ciphertext + tag concatenated
        ciphertext_with_tag = aesgcm.encrypt(iv, plaintext, aad)
        
        # The last 16 bytes are the authentication tag
        ciphertext = ciphertext_with_tag[:-self.TAG_SIZE]
        tag = ciphertext_with_tag[-self.TAG_SIZE:]
        
        return EncryptedData(
            ciphertext=ciphertext,
            iv=iv,
            tag=tag,
            aad=aad,
        )

    def decrypt(self, encrypted: EncryptedData) -> bytes:
        """
        Decrypt AES-256-GCM encrypted data.
        Verifies authentication tag to detect tampering.
        
        Args:
            encrypted: EncryptedData container
        
        Returns:
            Decrypted plaintext
        
        Raises:
            EncryptionError: If authentication fails (tampered data)
        """
        aesgcm = self._AESGCM(self.key)
        
        # Reconstruct the ciphertext+tag for decryption
        ciphertext_with_tag = encrypted.ciphertext + encrypted.tag
        
        try:
            plaintext = aesgcm.decrypt(
                encrypted.iv,
                ciphertext_with_tag,
                encrypted.aad,
            )
            return plaintext
        except Exception as e:
            raise EncryptionError(f"Decryption failed (possible tampering): {e}")

    def encrypt_str(self, plaintext: str, aad: Optional[bytes] = None) -> str:
        """Encrypt a string and return base64-encoded result."""
        encrypted = self.encrypt(plaintext.encode("utf-8"), aad)
        return base64.b64encode(encrypted.to_bytes()).decode("ascii")

    def decrypt_str(self, encrypted_b64: str) -> str:
        """Decrypt base64-encoded AES-GCM ciphertext."""
        encrypted = EncryptedData.from_bytes(base64.b64decode(encrypted_b64))
        plaintext = self.decrypt(encrypted)
        return plaintext.decode("utf-8")


# =============================================================================
# Key Derivation (HKDF)
# =============================================================================

class KeyDerivation:
    """
    Derive encryption keys from passwords using HKDF.
    Prevents weak/reused keys.
    """

    @staticmethod
    def derive_key(password: str, salt: Optional[bytes] = None, length: int = 32) -> tuple:
        """
        Derive a cryptographic key from a password using HKDF-SHA256.
        
        Args:
            password: User password
            salt: Random salt (generated if not provided)
            length: Key length in bytes (default 32 for AES-256)
        
        Returns:
            (derived_key, salt) tuple
        """
        try:
            from cryptography.hazmat.primitives.kdf.hkdf import HKDF
            from cryptography.hazmat.primitives import hashes
        except ImportError:
            raise EncryptionError("cryptography package required")

        if salt is None:
            salt = os.urandom(16)

        kdf = HKDF(
            algorithm=hashes.SHA256(),
            length=length,
            salt=salt,
            info=b"ai-research-encryption-key",
        )
        derived_key = kdf.derive(password.encode("utf-8"))
        return derived_key, salt


# =============================================================================
# ECB Detection (vulnerability scanner)
# =============================================================================

class ECBDetector:
    """Detects if data was encrypted with AES-ECB mode."""

    @staticmethod
    def detect_ecb_pattern(ciphertexts: list[bytes]) -> bool:
        """
        Detect ECB mode by checking for identical ciphertext blocks.
        
        ECB mode produces identical ciphertext for identical plaintext blocks.
        If we see duplicate 16-byte blocks, it's likely ECB.
        """
        if len(ciphertexts) < 2:
            return False

        block_size = 16  # AES block size
        seen_blocks = set()

        for ct in ciphertexts:
            for i in range(0, len(ct) - block_size + 1, block_size):
                block = ct[i:i + block_size]
                if block in seen_blocks:
                    return True  # Duplicate block found - likely ECB
                seen_blocks.add(block)

        return False

    @staticmethod
    def is_ecb_encryption(plaintext: bytes, ciphertext: bytes) -> bool:
        """
        Check if specific plaintext-ciphertext pair suggests ECB mode.
        Same plaintext should produce different ciphertext in secure modes.
        """
        # In ECB, identical plaintext blocks = identical ciphertext blocks
        # We can't definitively prove ECB without knowing the key,
        # but we can check for the pattern
        block_size = 16
        if len(plaintext) < block_size * 2:
            return False

        # Check if first two plaintext blocks are identical
        block1 = plaintext[:block_size]
        block2 = plaintext[block_size:block_size * 2]
        if block1 != block2:
            return False

        # If plaintext blocks are identical, check ciphertext blocks
        ct_block1 = ciphertext[:block_size]
        ct_block2 = ciphertext[block_size:block_size * 2]
        return ct_block1 == ct_block2


# =============================================================================
# Self-Test
# =============================================================================

def run_self_test() -> list:
    """Run self-tests. Returns list of failures."""
    failures = []

    # Test 1: Encrypt and decrypt round-trip
    try:
        crypto = SecureAESGCM()
        plaintext = b"Sensitive user data: admin=true"
        encrypted = crypto.encrypt(plaintext)
        decrypted = crypto.decrypt(encrypted)
        assert decrypted == plaintext, "Round-trip failed"
        assert encrypted.iv != b"\x00" * 12, "IV should be random"
        print("OK: Test 1 - Encrypt/decrypt round-trip")
    except Exception as e:
        failures.append(f"Test 1 failed: {e}")

    # Test 2: Different IVs for same plaintext
    try:
        crypto = SecureAESGCM()
        plaintext = b"Same data twice"
        enc1 = crypto.encrypt(plaintext)
        enc2 = crypto.encrypt(plaintext)
        assert enc1.iv != enc2.iv, "IVs should be different"
        assert enc1.ciphertext != enc2.ciphertext, "Ciphertexts should differ"
        print("OK: Test 2 - Random IV prevents deterministic output")
    except Exception as e:
        failures.append(f"Test 2 failed: {e}")

    # Test 3: Tampered ciphertext rejected
    try:
        crypto = SecureAESGCM()
        plaintext = b"Secret admin data"
        encrypted = crypto.encrypt(plaintext)
        # Tamper with ciphertext
        tampered = EncryptedData(
            ciphertext=encrypted.ciphertext[:-1] + bytes([encrypted.ciphertext[-1] ^ 0xFF]),
            iv=encrypted.iv,
            tag=encrypted.tag,
        )
        try:
            crypto.decrypt(tampered)
            failures.append("Test 3: Tampered data should be rejected")
        except EncryptionError:
            print("OK: Test 3 - Tampered ciphertext rejected")
    except Exception as e:
        failures.append(f"Test 3 failed: {e}")

    # Test 4: Key derivation
    try:
        key, salt = KeyDerivation.derive_key("my-strong-password")
        assert len(key) == 32, "Key should be 32 bytes"
        assert len(salt) == 16, "Salt should be 16 bytes"
        print("OK: Test 4 - Key derivation works")
    except Exception as e:
        failures.append(f"Test 4 failed: {e}")

    # Test 5: ECB detection
    try:
        detector = ECBDetector()
        # Create ECB-like ciphertext (identical blocks)
        ecb_ct = b"A" * 32  # Two identical blocks
        assert detector.detect_ecb_pattern([ecb_ct]) == False  # Only one ciphertext
        print("OK: Test 5 - ECB detection class available")
    except Exception as e:
        failures.append(f"Test 5 failed: {e}")

    # Test 6: String encrypt/decrypt
    try:
        crypto = SecureAESGCM()
        text = "User permission: admin=false"
        encoded = crypto.encrypt_str(text)
        decoded = crypto.decrypt_str(encoded)
        assert decoded == text
        print("OK: Test 6 - String encrypt/decrypt")
    except Exception as e:
        failures.append(f"Test 6 failed: {e}")

    return failures


if __name__ == "__main__":
    failures = run_self_test()
    if failures:
        print(f"\nFAILED: {len(failures)} test(s)")
        for f in failures:
            print(f"  - {f}")
    else:
        print("\nAll self-tests passed!")
        print("\nSecurity improvements over AES-ECB:")
        print("- Random IV per encryption (no deterministic output)")
        print("- AES-GCM provides authentication (tamper detection)")
        print("- HKDF key derivation from passwords")
        print("- ECB pattern detection for vulnerability scanning")
