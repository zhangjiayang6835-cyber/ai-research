import base64
import json
import os
import hmac
import hashlib
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# WARNING: This file contains a padding oracle vulnerability
# The encrypt/decrypt functions use CBC mode without authentication
class SessionCookieManager:
    def __init__(self, key=None):
        self.key = key or os.urandom(32)
        self.hmac_key = os.urandom(32)

    def encrypt(self, data: dict) -> str:
        """Encrypt session data to cookie string."""
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()
        
        cookie_data = iv + ciphertext
        mac = hmac.new(self.hmac_key, cookie_data, hashlib.sha256).digest()
        
        return base64.b64encode(mac + cookie_data).decode('utf-8')

    def decrypt(self, cookie: str) -> dict:
        """Decrypt cookie string to session data."""
            raw = base64.b64decode(cookie.encode('utf-8'))
            if len(raw) < 16:
                raise ValueError("Invalid cookie")
            
            # Extract MAC, verify before decryption to prevent padding oracle
            received_mac = raw[:32]
            iv = raw[32:48]
            ciphertext = raw[48:]
            
            cookie_data = iv + ciphertext
            expected_mac = hmac.new(self.hmac_key, cookie_data, hashlib.sha256).digest()
            
            # Constant-time comparison to prevent timing attacks
            if not hmac.compare_digest(received_mac, expected_mac):
                raise ValueError("Invalid cookie")
        except Exception:
            raise ValueError("Invalid cookie")
        
        cipher = Cipher(algorithms.AES(self.key), modes.CBC(iv))
        decryptor = cipher.decryptor()
        padded_data = decryptor.update(ciphertext) + decryptor.finalize()
        
        # Remove PKCS7 padding
        unpadder = padding.PKCS7(128).unpadder()
        data = unpadder.update(padded_data) + unpadder.finalize()
        
        return json.loads(data.decode('utf-8'))