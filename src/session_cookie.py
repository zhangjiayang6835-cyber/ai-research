import base64
import json
import os
import hmac
import hashlib
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend

# Secure key generation - in production, load from environment/secure vault
def _get_encryption_key():
    """Get or generate the encryption key from environment."""
    key = os.environ.get('SESSION_ENCRYPTION_KEY')
    if key:
        return key.encode('utf-8')
    # Fallback for development only - generate ephemeral key
    return os.urandom(32)

# Constant-time comparison to prevent timing attacks
def _constant_time_compare(val1, val2):
    """Compare two byte strings in constant time."""
    return hmac.compare_digest(val1, val2)

class SessionCookieManager:
    def __init__(self):
        self.key = _get_encryption_key()
        self.backend = default_backend()

    def encrypt_session(self, session_data: dict) -> str:
        """
        Encrypt session data using AES-GCM with authentication.
        """
        plaintext = json.dumps(session_data).encode('utf-8')
        
        # AES-GCM encryption with authentication tag
        aesgcm = AESGCM(self.key)
        nonce = os.urandom(12)  # 96-bit nonce for GCM
        ciphertext = aesgcm.encrypt(nonce, plaintext, None)
        
        # Format: base64(nonce + ciphertext + tag)
        # AESGCM.encrypt returns ciphertext + tag
        return base64.b64encode(nonce + ciphertext).decode('utf-8')

    def decrypt_session(self, encrypted_cookie: str) -> dict:
        """
        Decrypt and verify session data from encrypted cookie.
        FIXED: Uses authenticated encryption, no padding oracle possible.
        """
        try:
            data = base64.b64decode(encrypted_cookie)
            
            # Minimum size: 12 bytes nonce + 16 bytes tag + at least 1 byte ciphertext
            if len(data) < 29:
                raise ValueError("Invalid session cookie")
            
            nonce = data[:12]
            ciphertext = data[12:]
            
            aesgcm = AESGCM(self.key)
            plaintext = aesgcm.decrypt(nonce, ciphertext, None)
            
            return json.loads(plaintext.decode('utf-8'))
            
        except Exception:
            # FIXED: Generic error message prevents oracle attacks
            # All failures look identical - no information leakage
            raise ValueError("Invalid session cookie")

    def validate_session(self, encrypted_cookie: str) -> bool:
        """
        Check if session cookie is valid without exposing information.
        """
        try:
            self.decrypt_session(encrypted_cookie)
            return True
        except ValueError:
            return False


# Backward-compatible factory
def create_session_manager():
    """Create a new session manager with secure defaults."""
    return SessionCookieManager()


# Legacy alias for compatibility
SessionManager = SessionCookieManager