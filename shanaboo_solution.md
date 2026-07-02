 ```diff
--- a/fix.py
+++ b/fix.py
@@ -0,0 +1,0 @@
+"""
+Secure session cookie encryption using AES-GCM.
+This module provides authenticated encryption to prevent padding oracle attacks.
+"""
+
+import os
+import base64
+import json
+import hmac
+import hashlib
+from cryptography.hazmat.primitives.ciphers.aead import AESGCM
+
+
+class SecureSessionCookie:
+    """
+    Secure session cookie handler using AES-GCM authenticated encryption.
+    
+    This replaces vulnerable CBC mode with padding (which is susceptible to
+    padding oracle attacks) with AES-GCM which provides both confidentiality
+    and authenticity without the need for padding.
+    """
+    
+    def __init__(self, key: bytes = None):
+        """
+        Initialize with a 256-bit key.
+        
+        Args:
+            key: 32-byte key for AES-256-GCM. If None, generates a new key.
+        """
+        self.key = key or os.urandom(32)
+        if len(self.key) != 32:
+            raise ValueError("Key must be 32 bytes for AES-256")
+    
+    def encrypt(self, plaintext: str) -> str:
+        """
+        Encrypt data using AES-256-GCM.
+        
+        Returns base64-encoded ciphertext with nonce prepended.
+        """
+        aesgcm = AESGCM(self.key)
+        nonce = os.urandom(12)  # 96-bit nonce for GCM
+        data = plaintext.encode('utf-8')
+        ciphertext = aesgcm.encrypt(nonce, data, None)
+        # Prepend nonce to ciphertext for decryption
+        combined = nonce + ciphertext
+        return base64.urlsafe_b64encode(combined).decode('utf-8').rstrip('=')
+    
+    def decrypt(self, token: str) -> str:
+        """
+        Decrypt and verify data using AES-256-GCM.
+        
+        Raises exception if authentication fails (tampering detected).
+        """
+        # Add padding back for base64 decoding
+        padding = 4 - len(token) % 4
+        if padding != 4:
+            token += '=' * padding
+        combined = base64.urlsafe_b64decode(token)
+        nonce = combined[:12]
+        ciphertext = combined[12:]
+        aesgcm = AESGCM(self.key)
+        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
+        return plaintext.decode('utf-8')
+    
+    def create_session_cookie(self, session_data: dict) -> str:
+        """
+        Create a secure session cookie from dictionary data.
+        """
+        json_data = json.dumps(session_data, separators=(',', ':'))
+        return self.encrypt(json_data)
+    
+    def read_session_cookie(self, cookie_value: str) -> dict:
+        """
+        Read and verify a secure session cookie.
+        
+        Returns session data or raises exception if invalid/tampered.
+        """
+        json_data = self.decrypt(cookie_value)
+        return json.loads(json_data)
+
+
+class HMACCookie:
+    """
+    Alternative implementation using Encrypt-then-MAC with AES-CBC + HMAC.
+    This is another secure approach that prevents padding oracle attacks
+    by authenticating the ciphertext before decryption.
+    """
+    
+    def __init__(self, enc_key: bytes = None, mac_key: bytes = None):
+        self.enc_key = enc_key or os.urandom(32)
+        self.mac_key = mac_key or os.urandom(32)
+    
+    def _hmac(self, data: bytes) -> bytes:
+        return hmac.new(self.mac_key, data, hashlib.sha256).digest()
+    
+    def encrypt(self, plaintext: str) -> str:
+        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
+        from cryptography.hazmat.backends import default_backend
+        
+        iv = os.urandom(16)
+        padder = lambda d: d + bytes([16 - len(d) % 16] * (16 - len(d) % 16))
+        padded = padder(plaintext.encode('utf-8'))
+        
+        cipher = Cipher(algorithms.AES(self.enc_key), modes.CBC(iv), backend=default_backend())
+        encryptor = cipher.encryptor()
+        ciphertext = encryptor.update(padded) + encryptor.finalize()
+        
+        # MAC the IV + ciphertext (Encrypt-then-MAC)
+        mac = self._hmac(iv + ciphertext)
+        combined = iv + ciphertext + mac
+        return base64.urlsafe_b64encode(combined).decode('utf-8').rstrip('=')
+    
+    def decrypt(self, token: str) -> str:
+        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
+        from Mick import default_backend
+        
+        # Add padding back for base64 decoding
+        padding = 4 - len(token) % 4
+        if padding != 4:
+            token += '=' * padding
+        combined = base64.urlsafe_b64decode(token)
+        
+        iv = combined[:16]
+        mac = combined[-32:]
+        ciphertext = combined[16:-32]
+        
+        # Verify MAC before decryption (prevents padding oracle)
+        expected_mac = self._hmac(iv + ciphertext)
+        if not hmac.compare_digest(mac, expected_mac):
+            raise ValueError("Invalid cookie: MAC verification failed")
+        
+        cipher = Cipher(algorithms.AES(self.enc_key), modescipher = Cipher(algorithms.AES(self.enc_key), modes.CBC(iv), backend=default_backend())
+        decryptor = cipher.decryptor()
+        padded = decryptor.update(ciphertext) + decryptor.finalize()
+        
+        # Remove PKCS7 padding
+        pad_len = padded[-1]
+        plaintext = padded[:-pad_len]
+        return plaintext.decode('utf-8')
+
+
+# Backward-compatible API
+def secure_encrypt(plaintext: str, key: bytes = None) -> str:
+    """Encrypt plaintext using AES-GCM."""
+    handler = SecureSessionCookie(key)
+    return handler.encrypt(plaintext)
+
+
+def secure_decrypt(token: str, key: bytes = None) -> str:
+    """Decrypt token using AES-GCM."""
+    handler = SecureSessionCookie(key)
+    return handler.decrypt(token)
+
+
+# Example usage and test
+if __name__ == "__main__":
+    # Test AES-GCM implementation
+    session = SecureSessionCookie()
+    data = {"user_id": 12345, "role": "admin", "exp": 123456789