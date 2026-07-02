import base64
import json
import os
import hmac
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
from flask import request, make_response, abort


class SessionCookieManager:
    def __init__(self, secret_key=None):
        self.secret_key = secret_key or os.environ.get('SESSION_SECRET', 'default_secret_change_me')
        self.key = self._derive_key()
        self.hmac_key = self._derive_hmac_key()
    
    def _derive_key(self):
        """Derive AES key from secret."""
        # Simple key derivation - in production use PBKDF2 or Argon2
        return self.secret_key.encode('utf-8')[:32].ljust(32, b'\0')
    
    def _derive_hmac_key(self):
        """Derive HMAC key from secret (separate from encryption key)."""
        import hashlib
        h = hashlib.sha256(self.secret_key.encode('utf-8') + b'hmac_salt')
        return h.digest()
    
    def encrypt_cookie(self, data):
        """
        Encrypt session data for cookie storage.
        Args:
            data: Dictionary containing session data
        
        Uses AES-256-CBC with HMAC-SHA256 for authenticated encryption.
        Returns:
            Base64 encoded encrypted cookie value
        """
        # Encrypt
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()
        
        # Compute HMAC over IV + ciphertext
        mac = hmac.new(self.hmac_key, iv + ciphertext, hashlib.sha256).digest()
        
        # Combine IV + ciphertext + HMAC and encode
        # Format: IV (16 bytes) || ciphertext || HMAC (32 bytes)
        combined = iv + ciphertext + mac
        cookie_value = base64.b64encode(combined).decode('utf-8')
        
        return cookie_value
    
    def decrypt_cookie(self, cookie_value):
        
        Returns:
            Decrypted session data as dictionary
        Raises ValueError if authentication fails (prevents padding oracle).
        """
        if not cookie_value:
            return {}
        try:
            # Decode base64
            raw = base64.b64decode(cookie_value.encode('UTF-8'))
            
            # Minimum length: 16 (IV) + 0 (ciphertext) + 32 (HMAC)
            if len(raw) < 48:
                raise ValueError("Invalid cookie: too short")
            
            iv = raw[:self.BLOCK_SIZE]
            mac_received = raw[-32:]
            ciphertext = raw[self.BLOCK_SIZE:-32]
            
            # Verify HMAC before decryption (constant-time comparison)
            mac_computed = hmac.new(self.hmac_key, iv + ciphertext, hashlib.sha256).digest()
            if not hmac.compare_digest(mac_received, mac_computed):
                raise ValueError("Invalid cookie: authentication failed")
            
            # Decrypt
            cipher = Cipher(algorithms.AES(self.key), modes.CBC(iv), 
                          backend=default_backend())
            decryptor = cipher.decryptor()
            padded_data = decryptor.update(ciphertext) + decryptor.finalize()
            
            data = json.loads(padded_data.decode('utf-8'))
            return data
            
        except (ValueError, json.JSONDecodeError, UnicodeDecodeError):
            # Return empty session on any error
            return {}
    
        """
        cookie_value = request.cookies.get('session')
        if cookie_value:
            session = self.decrypt_cookie(cookie_value)
            if session is not None:
                return session
        return {}
    
    def set_session(self, response, data):
        response.set_cookie(
            'session', encrypted,
            httponly=True, secure=True, samesite='Lax'
        )