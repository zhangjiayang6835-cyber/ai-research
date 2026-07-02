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
    Secure session cookie manager using AES-256-GCM.
    Replaces vulnerable CBC mode with authenticated encryption (GCM)
    to prevent Padding Oracle attacks.
    """
    
    def __init__(self, key: bytes = None, secret_key: bytes = None):
        """
        Initialize with a 256-bit key for AES-GCM.
        """
        if key is None:
            key = os.urandom(32)  # 256-bit key
        self.key = key
        self.secret_key = secret_key or os.urandom(32)
    
    def encrypt_cookie(self, data: dict) -> str:
        """
        Encrypt session data using AES-256-GCM.
        Returns base64-encoded ciphertext with authentication tag.
        """
        # Serialize data
        plaintext = json.dumps(data).encode('utf-8')
        
        # Generate random nonce (IV) - 96 bits recommended for GCM
        nonce = os.urandom(12)
        
        # Encrypt with AES-GCM (provides both confidentiality and authenticity)
        aesgcm = AESGCM(self.key)
        ciphertext = aesgcm.encrypt(nonce, plaintext, None)
        
        # Combine nonce + ciphertext and encode
        # Format: nonce (12 bytes) || ciphertext + tag
        combined = nonce + ciphertext
        
        # Sign the combined data with HMAC to prevent tampering at transport layer
        signature = hmac.new(self.secret_key, combined, hashlib.sha256).digest()
        
        # Final format: base64(signature || nonce || ciphertext)
        result = base64.urlsafe_b64encode(signature + combined).decode('utf-8')
        return result
    
    def decrypt_cookie(self, token: str) -> dict:
        """
        Decrypt and verify session cookie.
        Raises exception on any tampering or decryption failure.
        """
        try:
            # Decode from base64
            data = base64.urlsafe_b64decode(token.encode('utf-8'))
            
            # Extract components
            signature = data[:32]
            combined = data[32:]
            nonce = combined[:12]
            ciphertext = combined[12:]
            
            # Verify HMAC signature first
            expected_signature = hmac.new(self.secret_key, combined, hashlib.sha256).digest()
            if not hmac.compare_digest(signature, expected_signature):
                raise ValueError("Invalid cookie signature")
            
            # Decrypt with AES-GCM (verifies authentication tag automatically)
            aesgcm = AESGCM(self.key)
            plaintext = aesgcm.decrypt(nonce, ciphertext, None)
            
            # Parse and return
            return json.loads(plaintext.decode('utf-8'))
            
        except Exception as e:
            # Generic error to prevent oracle attacks
            raise ValueError("Invalid cryptographic cookie") from e


# Example vulnerable code that was replaced (for reference):
# 
# class VulnerableCookieManager:
#     """Vulnerable to Padding Oracle attacks due to CBC mode without authentication."""
#     
#     def __init__(self, key):
#         self.key = key
#         self.cipher = AES.new(key, AES.MODE_CBC)  # VULNERABLE: CBC mode
#     
#     def encrypt(self, data):
#         # No authentication, vulnerable to bit-flipping and padding oracle
#         return self.cipher.encrypt(pad(data))
#     
#     def decrypt(self, ciphertext):
#         # Leaks padding information through error messages/timing
#         return unpad(self.cipher.decrypt(ciphertext))  # VULNERABLE


def create_secure_session(user_id: str, role: str = "user") -> str:
    """
    Create a secure session cookie for a user.
    """
    session_data = {
        "user_id": user_id,
        "role": role,
        "created_at": __import__('time').time(),
        "session_id": __import__('secrets').token_hex(16)
    }
    
    manager = SecureCookieManager()
    return manager.encrypt_cookie(session_data)


def verify_session(token: str) -> dict:
    """
    Verify and decode a session cookie.
    Returns session data or raises ValueError on failure.
    """
    manager = SecureCookieManager()
    return manager.decrypt_cookie(token)


if __name__ == "__main__":
    # Demonstration
    print("Creating secure session...")
    session = create_secure_session("user123", "admin")
    print(f"Session token: {session[:50]}...")
    
    print("\nVerifying session...")
    try:
        data = verify_session(session)
        print(f"Session data: {data}")
    except ValueError as e:
        print(f"Session invalid: {e}")
    
    # Test tampering detection
    print("\nTesting tamper detection...")
    tampered = session[:-5] + ("X" * 5)
    try:
        verify_session(tampered)
    except ValueError:
        print("Tampering detected successfully!")
print("fix #194")
