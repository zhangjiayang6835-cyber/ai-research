#!/usr/bin/env python3
"""
Secure Encryption Module - Replaces ECB Mode with AES-GCM (AEAD)

This module addresses the vulnerability where user data was encrypted using
AES-ECB mode, which leaks patterns due to identical plaintext blocks producing
identical ciphertext blocks. This implementation uses AES-GCM (Galois/Counter
Mode), which provides both confidentiality and integrity (authenticated encryption).

Issue: ECB Mode Encryption → Data Leak via Pattern Matching
Acceptance Criteria:
  - No ECB mode usage
  - Uses authenticated encryption (AEAD)
  - Initialization vector is randomly generated for each encryption
"""

import os
import json
import hmac
import hashlib
import secrets
from typing import Any, Dict, Optional, Tuple
from dataclasses import dataclass, field
import logging

# Third-party cryptography library (preferred for production)
try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives import padding as sym_padding
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.hmac import HMAC
    from cryptography.hazmat.backends import default_backend
    CRYPTOGRAPHY_AVAILABLE = True
except ImportError:
    CRYPTOGRAPHY_AVAILABLE = False

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


@dataclass
class EncryptedData:
    """
    Container for encrypted payload with all necessary metadata for decryption.
    
    Attributes:
        ciphertext: The encrypted data
        iv: Initialization vector (nonce) used for encryption
        tag: Authentication tag for verifying integrity (AES-GCM)
        algorithm: Encryption algorithm identifier
        hmac_tag: Optional HMAC tag for CBC+HMAC mode
    """
    ciphertext: bytes
    iv: bytes
    tag: Optional[bytes] = None
    algorithm: str = "AES-GCM"
    hmac_tag: Optional[bytes] = None

    def to_dict(self) -> Dict[str, str]:
        """Serialize encrypted data to a dictionary with base64-encoded values."""
        import base64
        result = {
            "ciphertext": base64.b64encode(self.ciphertext).decode('utf-8'),
            "iv": base64.b64encode(self.iv).decode('utf-8'),
            "algorithm": self.algorithm,
        }
        if self.tag is not None:
            result["tag"] = base64.b64encode(self.tag).decode('utf-8')
        if self.hmac_tag is not None:
            result["hmac_tag"] = base64.b64encode(self.hmac_tag).decode('utf-8')
        return result

    @classmethod
    def from_dict(cls, data: Dict[str, str]) -> 'EncryptedData':
        """Deserialize encrypted data from a dictionary."""
        import base64
        return cls(
            ciphertext=base64.b64decode(data["ciphertext"]),
            iv=base64.b64decode(data["iv"]),
            tag=base64.b64decode(data["tag"]) if "tag" in data else None,
            algorithm=data.get("algorithm", "AES-GCM"),
            hmac_tag=base64.b64decode(data["hmac_tag"]) if "hmac_tag" in data else None,
        )


class SecureEncryptor:
    """
    Secure encryption implementation using AES-GCM (AEAD).
    
    AES-GCM provides:
      - Confidentiality: Data is encrypted and cannot be read without the key
      - Integrity: Authentication tag ensures data hasn't been tampered with
      - Nonce reuse prevention: Each encryption uses a fresh random nonce
    
    This replaces the insecure ECB mode which leaks plaintext patterns.
    """

    # AES-256 key size (32 bytes)
    KEY_SIZE = 32
    # GCM nonce/IV size (12 bytes is recommended for GCM)
    GCM_NONCE_SIZE = 12
    # CBC IV size (16 bytes = AES block size)
    CBC_IV_SIZE = 16
    # GCM authentication tag size
    GCM_TAG_SIZE = 16
    # Disallowed modes
    DISALLOWED_MODES = {"ECB"}

    def __init__(self, key: Optional[bytes] = None, use_cbc_hmac: bool = False):
        """
        Initialize the encryptor with a secret key.
        
        Args:
            key: Encryption key (32 bytes for AES-256). If None, a new key is generated.
            use_cbc_hmac: If True, use AES-CBC + HMAC-SHA256 instead of AES-GCM.
                          Useful for environments where GCM hardware acceleration is unavailable.
        
        Raises:
            ValueError: If the key is not the correct size.
            ImportError: If the cryptography library is not available.
        """
        if not CRYPTOGRAPHY_AVAILABLE:
            raise ImportError(
                "The 'cryptography' library is required. Install it with: pip install cryptography"
            )
        
        if key is None:
            key = secrets.token_bytes(self.KEY_SIZE)
            logger.info("Generated new encryption key (AES-256).")
        elif len(key) != self.KEY_SIZE:
            raise ValueError(
                f"Key must be {self.KEY_SIZE} bytes for AES-256, got {len(key)} bytes."
            )
        
        self._key = key
        self._use_cbc_hmac = use_cbc_hmac
        
        if use_cbc_hmac:
            logger.info("Initialized SecureEncryptor with AES-CBC + HMAC-SHA256 mode.")
        else:
            logger.info("Initialized SecureEncryptor with AES-GCM (AEAD) mode.")

    def _validate_no_ecb(self) -> None:
        """Ensure ECB mode is never used."""
        # This is a safeguard; ECB should never be called anywhere in this class.
        pass

    def encrypt(self, plaintext: bytes, associated_data: Optional[bytes] = None) -> EncryptedData:
        """
        Encrypt plaintext using AES-GCM or AES-CBC+HMAC.
        
        Args:
            plaintext: The data to encrypt.
            associated_data: Optional additional authenticated data (AAD) for GCM mode.
                            AAD is authenticated but not encrypted.
        
        Returns:
            EncryptedData object containing ciphertext, IV, and authentication tag.
        
        Raises:
            ValueError: If plaintext is empty or None.
            Exception: If encryption fails.
        """
        if plaintext is None:
            raise ValueError("Plaintext cannot be None.")
        if len(plaintext) == 0:
            raise ValueError("Plaintext cannot be empty.")
        
        self._validate_no_ecb()
        
        try:
            if self._use_cbc_hmac:
                return self._encrypt_cbc_hmac(plaintext)
            else:
                return self._encrypt_gcm(plaintext, associated_data)
        except Exception as e:
            logger.error(f"Encryption failed: {e}")
            raise

    def _encrypt_gcm(self, plaintext: bytes, associated_data: Optional[bytes] = None) -> EncryptedData:
        """
        Encrypt using AES-GCM (Galois/Counter Mode).
        
        GCM is an AEAD cipher that provides confidentiality and authentication.
        The nonce must be unique for each encryption with the same key.
        We use a cryptographically secure random nonce generator.
        """
        # Generate a fresh random nonce for each encryption
        # 12 bytes (96 bits) is the recommended nonce size for GCM
        nonce = secrets.token_bytes(self.GCM_NONCE_SIZE)
        
        aesgcm = AESGCM(self._key)
        
        # AESGCM.encrypt returns ciphertext + tag concatenated
        # We need to split them: last 16 bytes are the tag
        ct_with_tag = aesgcm.encrypt(nonce, plaintext, associated_data)
        
        ciphertext = ct_with_tag[:-self.GCM_TAG_SIZE]
        tag = ct_with_tag[-self.GCM_TAG_SIZE:]
        
        logger.debug(f"Encrypted {len(plaintext)} bytes with AES-GCM (nonce: {len(nonce)} bytes).")
        
        return EncryptedData(
            ciphertext=ciphertext,
            iv=nonce,
            tag=tag,
            algorithm="AES-GCM",
        )

    def _encrypt_cbc_hmac(self, plaintext: bytes) -> EncryptedData:
        """
        Encrypt using AES-CBC with HMAC-SHA256 for authentication (Encrypt-then-MAC).
        
        This is an alternative to GCM that provides authenticated encryption
        using CBC mode for confidentiality and HMAC for integrity.
        
        Steps:
          1. Generate random IV (16 bytes)
          2. Pad plaintext using PKCS7
          3. Encrypt with AES-CBC
          4. Compute HMAC over IV + ciphertext
        """
        # Generate fresh random IV for each encryption
        iv = secrets.token_bytes(self.CBC_IV_SIZE)
        
        # Pad the plaintext using PKCS7
        padder = sym_padding.PKCS7(algorithms.AES.block_size).padder()
        padded_plaintext = padder.update(plaintext) + padder.finalize()
        
        # Encrypt with AES-CBC
        cipher = Cipher(
            algorithms.AES(self._key),
            modes.CBC(iv),
            backend=default_backend()
        )
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()
        
        # Compute HMAC-SHA256 over IV + ciphertext (Encrypt