import os
import base64
import secrets
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Hash import HMAC, SHA256

class UserDataEncryption:
    """AES-GCM authenticated encryption for user data storage"""
    
    def __init__(self, key: bytes = None):
        self.key = key or secrets.token_bytes(32)  # 256-bit key for AES-256-GCM
    
    def encrypt(self, plaintext: str) -> str:
        """Encrypt user data using AES-GCM mode with authentication"""
        if isinstance(plaintext, str):
            plaintext = plaintext.encode('utf-8')
        
        # Generate random 12-byte nonce (IV) for GCM
        nonce = secrets.token_bytes(12)
        
        cipher = AES.new(self.key, AES.MODE_GCM, nonce=nonce)
        ciphertext, tag = cipher.encrypt_and_digest(plaintext)
        
        # Combine nonce + ciphertext + tag for storage
        combined = nonce + ciphertext + tag
        return base64.b64encode(combined).decode('utf-8')
    
    def decrypt(self, ciphertext_b64: str) -> str:
        """Decrypt user data using AES-GCM mode with authentication verification"""
        try:
            combined = base64.b64decode(ciphertext_b64)
            
            # Extract nonce, ciphertext, and tag
            nonce = combined[:12]
            tag = combined[-16:]
            ciphertext = combined[12:-16]
            
            cipher = AES.new(self.key, AES.MODE_GCM, nonce=nonce)
            plaintext = cipher.decrypt_and_verify(ciphertext, tag)
            return plaintext.decode('utf-8')
        except (ValueError, KeyError) as e:
            raise ValueError(f"Decryption failed - authentication failed or data corrupted: {e}")
    
    @staticmethod
    def generate_key() -> bytes:
        """Generate a random 256-bit key for AES-256-GCM"""
        return secrets.token_bytes(32)
    
    def rotate_key(self, old_data: str) -> tuple:
        """Rotate encryption key and re-encrypt data with new key"""
        plaintext = self.decrypt(old_data)
        new_key = self.generate_key()
        old_key = self.key
        return new_encrypted, new_key

# Legacy compatibility wrapper
secure_encrypt = UserDataEncryption().encrypt
secure_decrypt = UserDataEncryption().decrypt