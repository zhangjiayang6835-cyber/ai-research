# Auto fix for zhangjiayang6835-cyber/ai-research#194
# 1782921258

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os
import base64
import json
import hmac
import hashlib


class SecureCookieManager:
    """
    Secure session cookie manager that prevents Padding Oracle attacks
    by using authenticated encryption (AES-GCM) instead of CBC mode.
    """
    
    def __init__(self, key: bytes = None):
        """
        Initialize with a 256-bit key. If no key provided, generates one.
        In production, load from secure key management (e.g., AWS KMS, HashiCorp Vault).
        """
        if key is None:
            key = os.urandom(32)  # 256-bit key
        elif len(key) not in (16, 24, 32):
            raise ValueError("Key must be 128, 192, or 256 bits")
        self.key = key
        self.aesgcm = AESGCM(self.key)
    
    def encrypt_cookie(self, plaintext: str, associated_data: bytes = b"session") -> str:
        """
        Encrypt session data using AES-GCM with authenticated encryption.
        Returns base64-encoded ciphertext with nonce prepended.
        """
        nonce = os.urandom(12)  # 96-bit nonce for GCM
        plaintext_bytes = plaintext.encode('utf-8')
        
        ciphertext = self.aesgcm.encrypt(
            nonce,
            plaintext_bytes,
            associated_data
        )
        
        # Format: nonce + ciphertext + tag (GCM appends tag to ciphertext)
        combined = nonce + ciphertext
        return base64.urlsafe_b64encode(combined).decode('ascii').rstrip('=')
    
    def decrypt_cookie(self, token: str, associated_data: bytes = b"session") -> str:
        """
        Decrypt and verify session cookie.
        Raises exception on tampering or decryption failure.
        """
        # Add padding for base64
        padding = 4 - len(token) % 4
        if padding != 4:
            token = token + '=' * padding
            
        combined = base64.urlsafe_b64decode(token.encode('ascii'))
        
        nonce = combined[:12]
        ciphertext = combined[12:]
        
        plaintext = self.aesgcm.decrypt(nonce, ciphertext, associated_data)
        return plaintext.decode('utf-8')


class HMACCookieManager:
    """
    Alternative: Encrypt-then-MAC using AES-CBC with HMAC.
    Prevents padding oracle by verifying MAC before decryption.
    """
    
    def __init__(self, enc_key: bytes = None, mac_key: bytes = None):
        self.enc_key = enc_key or os.urandom(32)
        self.mac_key = mac_key or os.urandom(32)
    
    def _hmac(self, data: bytes) -> bytes:
        return hmac.new(self.mac_key, data, hashlib.sha256).digest()
    
    def encrypt_cookie(self, plaintext: str) -> str:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        import struct
        
        # Pad plaintext
        padder = lambda p: p + (16 - len(p) % 16) * bytes([16 - len(p) % 16])
        padded = padder(plaintext.encode('utf-8'))
        
        # Encrypt
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(self.enc_key), modes.CBC(iv))
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(padded) + encryptor.finalize()
        
        # Compute MAC over IV || ciphertext
        mac = self._hmac(iv + ciphertext)
        
        # Format: IV || ciphertext || MAC
        combined = iv + ciphertext + mac
        return base64.urlsafe_b64encode(combined).decode('ascii').rstrip('=')
    
    def decrypt_cookie(self, token: str) -> str:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        
        # Add padding
        padding = 4 - len(token) % 4
        if padding != 4:
            token = token + '=' * padding
            
        combined = base64.urlsafe_b64decode(token.encode('ascii'))
        
        # Extract components
        iv = combined[:16]
        mac = combined[-32:]
        ciphertext = combined[16:-32]
        
        # Verify MAC FIRST (constant-time comparison)
        expected_mac = self._hmac(iv + ciphertext)
        if not hmac.compare_digest(mac, expected_mac):
            raise ValueError("Invalid MAC - possible tampering detected")
        
        # Only decrypt if MAC is valid
        cipher = Cipher(algorithms.AES(self.enc_key), modes.CBC(iv))
        decryptor = cipher.decryptor()
        padded = decryptor.update(ciphertext) + decryptor.finalize()
        
        # Remove PKCS7 padding
        pad_len = padded[-1]
        return padded[:-pad_len].decode('utf-8')


# Backward-compatible API
def create_secure_manager(key: bytes = None) -> SecureCookieManager:
    """Factory function to create a secure cookie manager."""
    return SecureCookieManager(key)


def encrypt_session_data(data: dict, secret_key: bytes = None) -> str:
    """
    Encrypt session data securely, preventing padding oracle attacks.
    """
    manager = SecureCookieManager(secret_key)
    json_data = json.dumps(data, separators=(',', ':'))
    return manager.encrypt_cookie(json_data)


def decrypt_session_data(token: str, secret_key: bytes = None) -> dict:
    """
    Decrypt and verify session data.
    """
    manager = SecureCookieManager(secret_key)
    json_data = manager.decrypt_cookie(token)
    return json.loads(json_data)
print("fix #194")
