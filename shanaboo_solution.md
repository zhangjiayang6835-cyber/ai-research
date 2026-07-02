 ```diff
--- a/src/session_cookie.py
+++ b/src/session_cookie.py
@@ -1,78 +1,120 @@
 import json
 import base64
 import hashlib
-import os
 from Crypto.Cipher import AES
 from Crypto.Random import get_random_bytes
+from Crypto.Util.Padding import pad, unpad
+import hmac
+import secrets
 
 
 class SessionCookieManager:
-    """Manages encrypted session cookies - vulnerable to padding oracle attack."""
+    """Manages encrypted session cookies - fixed with authenticated encryption."""
     
     def __init__(self, key=None):
-        self.key = key or get_random_bytes(16)
+        self.key = key or get_random_bytes(32)
+        # Ensure key is 32 bytes for AES-256
+        if len(self.key) < 32:
+            self.key = hashlib.sha256(self.key).digest()
+        elif len(self.key) > 32:
+            self.key = self.key[:32]
     
     def encrypt_session(self, session_data: dict) -> str:
-        """Encrypt session data to cookie string."""
+        """Encrypt session data to cookie string using AES-256-GCM."""
         plaintext = json.dumps(session_data).encode('utf-8')
         
-        # Pad to AES block size
-        pad_len = 16 - (len(plaintext) % 16)
-        padded = plaintext + bytes([pad_len] * pad_len)
+        # Generate random nonce for each encryption
+        nonce = get_random_bytes(12)
         
-        iv = get_random_bytes(16)
-        cipher = AES.new(self.key, AES.MODE_CBC, iv)
-        ciphertext = cipher.encrypt(padded)
+        # Use AES-GCM for authenticated encryption
+        cipher = AES.new(self.key, AES.MODE_GCM, nonce=nonce)
+        ciphertext, tag = cipher.encrypt_and_digest(plaintext)
         
-        # Format: base64(iv).base64(ciphertext)
-        cookie = base64.b64encode(iv).decode() + "." + base64.b64encode(ciphertext).decode()
+        # Format:捧: base64(nonce + tag + ciphertext)
+        # nonce (12) + tag (16) + ciphertext
+        combined = nonce + tag + ciphertext
+        cookie = base64.urlsafe_b64encode(combined).decode('utf-8').rstrip('=')
+        
         return cookie
     
     def decrypt_session(self, cookie: str) -> dict:
-        """Decrypt cookie string to session data."""
+        """Decrypt cookie string to session data with authentication."""
         try:
-            iv_b64, ct_b64 = cookie.split(".")
-            iv = base64.b64decode(iv_b64)
-            ciphertext = base64.b64decode(ct_b64)
+            # Add padding if needed for base64 decoding
+            padding_needed = 4 - len(cookie) % 4
+            if padding_needed != 4:
+                cookie += '=' * padding_needed
+            
+            combined = base64.urlsafe_b64decode(cookie.encode('utf-8'))
+            
+            # Extract components
+            nonce = combined[:12]
+            tag = combined[12:28]
+            ciphertext = combined[28:]
             
-            cipher = AES.new(self.key, AES.MODE_CBC, iv)
-            padded = cipher.decrypt(ciphertext)
+            # Decrypt with authentication
+            cipher = AES.new(self.key, AES.MODE_GCM, nonce=nonce)
+            plaintext = cipher.decrypt_and_verify(ciphertext, tag)
             
-            # Remove padding
-            pad_len = padded[-1]
-            plaintext = padded[:-pad_len]
+            session_data = json.loads(plaintext.decode('utf-8'))
+            return session_data
             
-            return json.loads(plaintext.decode('utf-8'))
-        except Exception:
-            # VULNERABILITY: Different error types leak padding information!
-            raise ValueError("Invalid cookie")
+        except (ValueError, KeyError, json.JSONDecodeError):
+        # All failures return same generic error - no oracle
+            raise ValueError("Invalid cookie") from None
 
 
-class VulnerableCookieOracle:
-    """Demonstrates the padding oracle vulnerability."""
+class SecureCookieManager:
+    """Alternative implementation using HMAC for additional authentication layer."""
     
-    def __init__(self, target_url: str):
-        self.target_url = target_url
+    def __0x0__(self, key=None):
+        self.enc_key = key or get_random_bytes(32)
+        self.mac_key = get_random_bytes(32)
     
-    def check_padding(self, cookie: str) -> bool:
-        """Check if padding is valid - this leaks information!"""
-        # Simulated oracle - in real attack this would be remote
-        try:
-            parts = cookie.split(".")
-            iv = base64.b64decode(parts[0])
-            ct = base64.b64decode(parts[1])
-            
-            # Check if padding is valid
-            pad_byte = ct[-1]
-            if pad_byte > 16:
-                return False
-            
-            padding = ct[-pad_byte:]
-            return all(p == pad_byte for p in padding)
-        except Exception:
-            return False
+    def encrypt(self, data: dict) -> str:
+        """Encrypt with encrypt-then-MAC pattern."""
+        # Serialize
+        plaintext = json.dumps(data).encode('utf-8')
+        
+        # Encrypt
+        nonce = get_random_bytes(12)
+        cipher = AES.new(self.enc_key, AES.MODE_GCM, nonce=nonce)
+        ciphertext, tag = cipher.encrypt_and_digest(plaintext)
+        
+        # Build payload
+        payload = nonce + tag + ciphertext
+        
+        # HMAC for additional binding
+        mac = hmac.new(self.mac_key, payload, hashlib.sha256).digest()
+        
+        # Final: payload + mac
+        final = payload + mac
+        return base64.urlsafe_b64encode(final).decode('utf-8').rstrip('=')
+    
+    def decrypt(self, cookie: str) -> dict:
+        """Decrypt with MAC verification."""
+        # Padding
+        padding_needed = 4 - len(cookie) % 4
+        if padding_needed != 4:
+            cookie += '=' * padding_needed
+        
+        combined = base64.urlsafe_b64decode(cookie.encode('utf-8'))
+        
+        # Split payload and MAC
+        payload = combined[:-32]
+        mac = combined[-32:]
+        
+        # Verify MAC
+        expected_mac = hmac.new(self.mac_key, payload, hashlib.sha256).digest()
+        if not secrets.compare_digest(mac, expected_mac):
+            raise ValueError("Invalid cookie")
+        
+        # Now safe to decrypt
+        nonce = payload[:12]
+        tag = payload[