import base64
import json
import os
import hmac
import hashlib
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend


    """
    Manages encrypted session cookies for web application.
    """
    
    def __init__(self, key=None):
        """
        Initialize with a secret key.
        If no key provided, generates a random one (for demo purposes).
        """
        self.key = key or os.urandom(32)  # 256-bit key for AES-256-GCM
    
    def encrypt_session(self, session_data: dict) -> str:
        """
        Encrypt session data using AES-GCM with authentication tag.
        Returns base64-encoded ciphertext.
        """
        # Serialize session data with timestamp for replay protection
        payload = {
            'data': session_data,
            'nonce': base64.b64encode(os.urandom(16)).decode('ascii')
        }
        plaintext = json.dumps(payload).encode('utf-8')
        
        # Generate random nonce for GCM
        nonce = os.urandom(12)  # 96-bit nonce recommended for GCM
        
        # Encrypt with AES-GCM
        aesgcm = AESGCM(self.key)
        ciphertext = aesgcm.encrypt(nonce, plaintext, None)
        
        # Format: nonce (12 bytes) + ciphertext + tag (16 bytes)
        # All combined in ciphertext by AESGCM
        encrypted_package = nonce + ciphertext
        
        return base64.b64encode(encrypted_package).decode('ascii')
    
    def decrypt_session(self, encrypted_data: str) -> dict:
        """
        Decrypt and verify session data using AES-GCM.
        Raises exception on tampering or decryption failure.
        """
        raw = base64.b64decode(encrypted_data)
        
        # Extract nonce and ciphertext
        nonce = raw[:12]
        ciphertext = raw[12:]
        
        # Decrypt with AES-GCM (authenticates automatically)
        aesgcm = AESGCM(self.key)
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
        
        # Parse and return session data
        payload = json.loads(plaintext.decode('utf-8'))
        return payload['data']
    
    def rotate_key(self, new_key=None):
        """
        Rotate encryption key. Returns old key for re-encryption.
        """
        old_key = self.key
        self.key = new_key or os.urandom(32)
        return old_key
    
    @staticmethod
    def generate_key():
        """Generate a cryptographically secure random key."""
        return os.urandom(32)