"""Fix #1475: ECB mode encryption leaks plaintext patterns.

User data was encrypted with AES-ECB, so identical 16-byte blocks produce
identical ciphertext blocks (e.g. repeated role tokens). Replace with
AES-256-GCM authenticated encryption and a fresh random nonce per operation.
"""

from __future__ import annotations

import os
import secrets
from dataclasses import dataclass

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

_NONCE_LEN = 12
_KEY_LEN = 32


class EncryptionError(ValueError):
    """Raised when ciphertext is malformed or fails authentication."""


@dataclass(frozen=True)
class EncryptedUserData:
    """AEAD payload: random nonce prepended to ciphertext+tag."""

    blob: bytes

    @property
    def nonce(self) -> bytes:
        return self.blob[:_NONCE_LEN]


class UserDataEncryptor:
    """Store user fields with AES-256-GCM (AEAD); never ECB."""

    def __init__(self, key: bytes | None = None) -> None:
        raw_key = key or secrets.token_bytes(_KEY_LEN)
        if len(raw_key) != _KEY_LEN:
            raise ValueError("AES-256-GCM requires a 32-byte key")
        self._key = raw_key

    @staticmethod
    def generate_key() -> bytes:
        return AESGCM.generate_key(bit_length=256)

    def encrypt(self, plaintext: str, *, context: bytes = b"user-data-v1") -> EncryptedUserData:
        nonce = os.urandom(_NONCE_LEN)
        aesgcm = AESGCM(self._key)
        ciphertext = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), context)
        return EncryptedUserData(blob=nonce + ciphertext)

    def decrypt(self, payload: EncryptedUserData, *, context: bytes = b"user-data-v1") -> str:
        if len(payload.blob) < _NONCE_LEN + 16:
            raise EncryptionError("ciphertext too short")

        nonce = payload.blob[:_NONCE_LEN]
        ciphertext = payload.blob[_NONCE_LEN:]
        aesgcm = AESGCM(self._key)
        try:
            plaintext = aesgcm.decrypt(nonce, ciphertext, context)
        except InvalidTag as exc:
            raise EncryptionError("authentication failed") from exc
        return plaintext.decode("utf-8")
