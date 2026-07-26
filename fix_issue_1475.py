"""
Fix for Issue #1475 — ECB Mode Encryption → Data Leak via Pattern Matching

Vulnerability
-------------
User data was encrypted using AES-ECB (Electronic Codebook) mode. In ECB mode,
identical plaintext blocks produce identical ciphertext blocks. An attacker with
access to the encrypted data can identify patterns — e.g., distinguish "admin"
permission bits from "user" permission bits — by matching repeated ciphertext
blocks, completely breaking confidentiality.

Fix
---
1. Replace AES-ECB with AES-256-GCM (authenticated encryption)
2. Use a random 12-byte nonce for every encryption operation
3. Verify authenticity via GCM's built-in MAC tag (no padding oracle)
4. Include context binding via AAD (Additional Authenticated Data)

Acceptance Criteria
-------------------
- [x] ECB mode is not used
- [x] Uses authenticated encryption (AEAD — AES-GCM)
- [x] Initialization vector / nonce is randomly generated
"""

from __future__ import annotations

import os
import base64
from typing import Optional


class SecureDataEncryptor:
    """
    Encrypts user data using AES-256-GCM (authenticated encryption).

    Each encryption uses a fresh random 12-byte nonce. The ciphertext
    includes the nonce + GCM tag + encrypted data in a single URL-safe
    base64 payload. AAD binds ciphertext to a context label, preventing
    ciphertext reuse across different data types.
    """

    def __init__(self, key: Optional[bytes] = None):
        """
        Initialize the encryptor with an AES-256 key.

        Args:
            key: 32-byte AES key. If None, a random key is generated.
        """
        if key is not None and len(key) != 32:
            raise ValueError("Key must be exactly 32 bytes for AES-256")
        self._key = key or os.urandom(32)

    def encrypt(self, plaintext: bytes, aad: bytes = b"") -> str:
        """
        Encrypt plaintext using AES-256-GCM.

        Args:
            plaintext: Data to encrypt (bytes).
            aad: Additional Authenticated Data — binds ciphertext to context.

        Returns:
            URL-safe base64 string: nonce (12 bytes) || ciphertext || tag (16 bytes)
        """
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        aesgcm = AESGCM(self._key)
        nonce = os.urandom(12)  # 96-bit random nonce — never reuse with same key
        ciphertext = aesgcm.encrypt(nonce, plaintext, aad)
        # ciphertext = encrypted data + GCM tag (16 bytes)
        payload = nonce + ciphertext
        return base64.urlsafe_b64encode(payload).decode()

    def decrypt(self, encoded: str, aad: bytes = b"") -> Optional[bytes]:
        """
        Decrypt data previously encrypted with ``encrypt``.

        Args:
            encoded: URL-safe base64 string from a prior ``encrypt`` call.
            aad: Must match the AAD used during encryption.

        Returns:
            Original plaintext bytes, or None if authentication fails
            (wrong key, tampered ciphertext, or AAD mismatch).
        """
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        try:
            payload = base64.urlsafe_b64decode(encoded)
            if len(payload) < 12 + 16:  # nonce + min ciphertext + tag
                return None
            nonce = payload[:12]
            ct = payload[12:]
            aesgcm = AESGCM(self._key)
            return aesgcm.decrypt(nonce, ct, aad)
        except Exception:
            # All errors produce None — no padding oracle, no information leak
            return None

    def encrypt_str(self, plaintext: str, context: str = "") -> str:
        """Convenience: encrypt a string with optional context label as AAD."""
        return self.encrypt(plaintext.encode("utf-8"), aad=context.encode())

    def decrypt_str(self, encoded: str, context: str = "") -> Optional[str]:
        """Convenience: decrypt to a string with context label as AAD."""
        result = self.decrypt(encoded, aad=context.encode())
        if result is None:
            return None
        return result.decode("utf-8")

    @property
    def key(self) -> bytes:
        """Return the encryption key (handle with care!)."""
        return self._key


def demonstrate_vulnerability():
    """
    Demonstrate why ECB is broken and GCM is secure.

    ECB: identical plaintext blocks → identical ciphertext blocks.
    GCM: no two ciphertexts are alike, even for identical plaintexts.
    """
    print("=" * 60)
    print("ECB vs GCM — Pattern Leakage Demonstration")
    print("=" * 60)

    # A plaintext with repeated blocks (16-byte AES blocks)
    # ECB requires padding to block boundary; use PKCS7
    from cryptography.hazmat.primitives import padding as aes_padding

    repeated_pt = b"AAAAABBBBBCCCCCD"  # 16 bytes — one block
    repeated_pt2 = b"AAAAABBBBBCCCCCD"  # Same 16 bytes = identical ciphertext
    unique_pt = b"0000011111222223"  # Different 16 bytes

    # --- ECB (broken) ---
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

    ecb_key = os.urandom(32)
    ecb_cipher = Cipher(algorithms.AES(ecb_key), modes.ECB())
    ecb_enc = ecb_cipher.encryptor()
    ecb_enc2 = Cipher(algorithms.AES(ecb_key), modes.ECB()).encryptor()

    ecb_ct_repeated = ecb_enc.update(repeated_pt) + ecb_enc.finalize()
    ecb_ct_repeated2 = ecb_enc2.update(repeated_pt2) + ecb_enc2.finalize()
    print(f"\nECB encryption with same plaintext — two independent operations:")
    block1 = ecb_ct_repeated[:16]
    block2 = ecb_ct_repeated2[:16]
    print(f"  Ciphertext 1: {ecb_ct_repeated.hex()}")
    print(f"  Ciphertext 2: {ecb_ct_repeated2.hex()}")
    print(f"  Blocks identical? {block1 == block2} ← PATTERN LEAK!")

    ecb_enc3 = Cipher(algorithms.AES(ecb_key), modes.ECB()).encryptor()
    ecb_ct_unique = ecb_enc3.update(unique_pt) + ecb_enc3.finalize()
    print(f"\nECB ciphertext (different plaintext): {ecb_ct_unique.hex()}")

    if block1 == block2:
        print("\n✅ PROOF: ECB reveals repeated plaintext patterns!")
    else:
        print("\n❌ Test failed")

    # --- GCM (secure) ---
    encryptor = SecureDataEncryptor()
    gcm_ct1 = encryptor.encrypt(repeated_pt)
    gcm_ct2 = encryptor.encrypt(repeated_pt)  # Same plaintext, same key
    gcm_ct3 = encryptor.encrypt(unique_pt)
    print(f"\nGCM ciphertext 1 (repeated PT): {gcm_ct1[:40]}...")
    print(f"GCM ciphertext 2 (repeated PT): {gcm_ct2[:40]}...")
    print(f"GCM ciphertext 3 (unique PT):   {gcm_ct3[:40]}...")
    print(f"  CT1==CT2? {gcm_ct1 == gcm_ct2} ← No pattern leak!")
    print(f"  CT1==CT3? {gcm_ct1 == gcm_ct3} ← No pattern leak!")

    if gcm_ct1 != gcm_ct2:
        print("\n✅ PROOF: GCM produces different ciphertexts for same plaintext!")
    else:
        print("\n❌ Test failed")


def run_tests():
    """Run automated tests for the fix."""
    print("=" * 60)
    print("Running Tests for Issue #1475 Fix")
    print("=" * 60)

    # Test 1: Basic encrypt/decrypt round-trip
    enc = SecureDataEncryptor()
    data = b"Sensitive user data - role=admin"
    encoded = enc.encrypt(data)
    decoded = enc.decrypt(encoded)
    assert decoded == data, "Round-trip encryption failed"
    print("✓ Test 1: Basic encrypt/decrypt round-trip")

    # Test 2: String convenience methods
    text = "user@example.com:premium_subscriber"
    encoded_str = enc.encrypt_str(text)
    decoded_str = enc.decrypt_str(encoded_str)
    assert decoded_str == text, "String round-trip failed"
    print("✓ Test 2: String encrypt/decrypt round-trip")

    # Test 3: AAD binding — wrong AAD must fail
    encoded_aad = enc.encrypt(b"secret", aad=b"user_profile")
    result_wrong_aad = enc.decrypt(encoded_aad, aad=b"payment_info")
    assert result_wrong_aad is None, "AAD binding failed — wrong AAD should not decrypt"
    result_correct_aad = enc.decrypt(encoded_aad, aad=b"user_profile")
    assert result_correct_aad == b"secret", "AAD binding failed — correct AAD should decrypt"
    print("✓ Test 3: AAD context binding")

    # Test 4: Tampered ciphertext must fail
    encoded_tamper = enc.encrypt(b"important data")
    # Flip a byte in the base64 payload
    payload = bytearray(base64.urlsafe_b64decode(encoded_tamper))
    payload[len(payload) // 2] ^= 0x01  # flip a bit
    tampered = base64.urlsafe_b64encode(bytes(payload)).decode()
    result_tampered = enc.decrypt(tampered)
    assert result_tampered is None, "Tampered ciphertext should not decrypt"
    print("✓ Test 4: Tamper detection via GCM authentication")

    # Test 5: Key must be 32 bytes for AES-256
    try:
        SecureDataEncryptor(key=b"short")
        assert False, "Should have raised ValueError"
    except ValueError:
        pass
    print("✓ Test 5: Key length validation")

    # Test 6: Same plaintext → different ciphertext every time
    enc2 = SecureDataEncryptor()
    results = set()
    for _ in range(5):
        results.add(enc2.encrypt(b"constant_data"))
    assert len(results) == 5, "Same plaintext should produce different ciphertexts"
    print("✓ Test 6: Non-deterministic encryption (random nonces)")

    # Test 7: Empty data
    empty_enc = enc.encrypt(b"")
    empty_dec = enc.decrypt(empty_enc)
    assert empty_dec == b"", "Empty data round-trip failed"
    print("✓ Test 7: Empty data handling")

    print("\n" + "=" * 60)
    print("✅ All 7 tests passed for Issue #1475: ECB → GCM Migration")
    print("=" * 60)


if __name__ == "__main__":
    demonstrate_vulnerability()
    print()
    run_tests()
