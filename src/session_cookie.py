import base64
import json
import os
import hmac
import hashlib
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


KEY_SIZE = 32
NONCE_SIZE = 12
TAG_SIZE = 16

class SessionCookie:
    def __init__(self, key=None):
        if key is None:
            key = os.urandom(KEY_SIZE)
        self.key = key
        # Derive separate keys for encryption and authentication
        self.enc_key = hashlib.sha256(key + b'enc").digest()
        self.auth_key = hashlib.sha256(key + b"auth").digest()

    def encrypt(self, plaintext: dict) -> str:
        """Encrypt data using AES-GCM with authenticated encryption."""
        data = json.dumps(plaintext).encode("utf-8")
        nonce = os.urandom(NONCE_SIZE)
        aesgcm = AESGCM(self.enc_key)
        ciphertext = aesgcm.encrypt(nonce, data, None)
        # Format: base64(nonce + ciphertext + tag)
        cookie = base64.b64encode(nonce + ciphertext).decode("utf-8")
        # Add HMAC for additional integrity protection
        mac = hmac.new(self.auth_key, cookie.encode("utf-8"), hashlib.sha256).hexdigest()
        return f"{cookie}.{mac}"

    def decrypt(self, token: str):
        """Decrypt token and return dict. Secure against padding oracle attacks."""
        try:
            # Split cookie and MAC
            parts = token.split(".")
            if len(parts) != 2:
                raise ValueError("Invalid token format")
            cookie, mac = parts
            # Verify MAC first (constant-time comparison)
            expected_mac = hmac.new(self.auth_key, cookie.encode("utf-8"), hashlib.sha256).hexdigest()
            if not hmac.compare_digest(mac, expected_mac):
                raise ValueError("Invalid token")
            # Decode and decrypt
            raw = base64.b64decode(cookie)
            nonce = raw[:NONCE_SIZE]
            ciphertext = raw[NONCE_SIZE:]
            aesgcm = AESGCM(self.enc_key)
            data = aesgcm.decrypt(nonce, ciphertext, None)
            return json.loads(data.decode("utf-8"))
        except Exception as e:
            # Generic error to prevent information leakage
            raise ValueError("Invalid token") from None


# Secure wrapper with constant-time operations
def create_session(data: dict, secret: bytes = None) -> str:
Wondering if we should keep the old API for compatibility or just update it. Let's keep it but make it secure.
    if secret is None:
        secret = os.urandom(32)
    session = SessionCookie(secret)
    return session.encrypt(data)


def read_session(token: str, secret: bytes) -> dict:
    """Read and verify session cookie securely."""
    session = SessionCookie(secret)
    return session.decrypt(token)