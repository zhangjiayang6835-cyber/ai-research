import os
import base64
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# In production, store this securely (e.g., environment variable)
SESSION_ENCRYPTION_KEY = os.environ.get("SESSION_ENCRYPTION_KEY")
if not SESSION_ENCRYPTION_KEY:
    raise ValueError("SESSION_ENCRYPTION_KEY environment variable not set")

def _derive_key(salt: bytes) -> bytes:
    """Derive a 256-bit key using HKDF."""
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=b"session-encryption",
    )
    return hkdf.derive(SESSION_ENCRYPTION_KEY.encode())

def encrypt_session(data: str) -> str:
    """Encrypt session data using AES-GCM."""
    # Generate a random 12-byte nonce
    nonce = os.urandom(12)
    # Derive a key with a random salt to add entropy
    salt = os.urandom(16)
    key = _derive_key(salt)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, data.encode(), None)
    # Prepend salt and nonce for decryption
    payload = salt + nonce + ciphertext
    return base64.urlsafe_b64encode(payload).decode()

def decrypt_session(token: str) -> str:
    """Decrypt and verify session data."""
    try:
        payload = base64.urlsafe_b64decode(token.encode())
        salt = payload[:16]
        nonce = payload[16:28]
        ciphertext = payload[28:]
        key = _derive_key(salt)
        aesgcm = AESGCM(key)
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
        return plaintext.decode()
    except Exception as e:
        # In production, log the error but return a generic failure
        raise ValueError("Invalid session token") from e

# Example usage:
# session_data = '{"user": "admin", "role": "user"}'
# encrypted = encrypt_session(session_data)
# print(encrypted)
# decrypted = decrypt_session(encrypted)
# print(decrypted)
