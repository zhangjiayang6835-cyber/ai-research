# Auto fix for zhangjiayang6835-cyber/ai-research#194
# 1782921258

"""
Secure session cookie encryption using AES-GCM.
Fixes Padding Oracle Attack vulnerability by using authenticated encryption.
"""

import os
import base64
import json
import hmac
import hashlib
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class SecureCookieManager:
    """
    Secure cookie encryption using AES-GCM with authentication.
    Replaces vulnerable CBC mode that was susceptible to padding oracle attacks.
    """
    
    def __init__(self, key: bytes = None):
        """Initialize with a 256-bit key."""
        self.key = key or os.urandom(32)
        self._key_hmac = hashlib.sha256(self.key + b'hmac').digest()
    
    def encrypt_cookie(self, data: dict) -> str:
        """
        Encrypt session data using AES-GCM.
        Returns base64-encoded ciphertext with nonce and tag.
        """
        # Serialize data
        plaintext = json.dumps(data).encode('utf-8')
        
        # Generate random nonce (IV) - 96 bits for GCM
        nonce = os.urandom(12)
        
        # Encrypt with AES-GCM
        aesgcm = AESGCM(self.key)
        ciphertext = aesgcm.encrypt(nonce, plaintext, None)
        
        # Format: nonce || ciphertext (tag is appended by AESGCM)
        # Combine and encode
        combined = nonce + ciphertext
        return base64.urlsafe_b64encode(combined).decode('ascii').rstrip('=')
    
    def decrypt_cookie(self, token: str) -> dict:
        """
        Decrypt and verify session cookie.
        Raises ValueError if tampering is detected.
        """
        # Restore padding
        padding = 4 - len(token) % 4
        if padding != 4:
            token += '=' * padding
        
        # Decode
        combined = base64.urlsafe_b64decode(token.encode('ascii'))
        
        # Extract nonce and ciphertext
        nonce = combined[:12]
        ciphertext = combined[12:]
        
        # Decrypt - AESGCM will verify authentication tag
        aesgcm = AESGCM(self.key)
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
        
        return json.loads(plaintext.decode('utf-8'))
    
    def create_session_cookie(self, session_data: dict) -> str:
        """Create a secure session cookie string."""
        return self.encrypt_cookie(session_data)
 supplemental
    def verify_and_decrypt(self, cookie_value: str) -> dict:
        """Verify and decrypt a session cookie."""
        return self.decrypt_cookie(cookie_value)


# Backward-compatible functions for existing code
def encrypt_session(data: dict, key: bytes = None) -> str:
    """Encrypt session data securely."""
    manager = SecureCookieManager(key)
    return manager.encrypt_cookie(data)


def decrypt_session(token: str, key: bytes = None) -> dict:
    """Decrypt session data with integrity verification."""
    manager = SecureCookieManager(key)
    return manager.decrypt_cookie(token)
print("fix #194")
