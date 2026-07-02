# Auto fix for zhangjiayang6835-cyber/ai-research#194
# 1782921258

import hmac
import hashlib
import base64
import json


def create_jwt(payload, secret):
    """Create a JWT with HMAC-SHA256 signature using proper key separation."""
    header = {"alg": "HS256", "typ": "JWT"}
    header_b64 = base64.urlsafe_b64encode(json.dumps(header, separators=(',', ':')).encode()).rstrip(b'=')
    payload_b64 = base64.urlsafe_b64encode(json.dumps(payload, separators=(',', ':')).encode()).rstrip(b'=')
    
    message = header_b64 + b'.' + payload_b64
    # Use hmac.compare_digest and proper HMAC to prevent timing attacks and hash length extension
    signature = hmac.new(secret.encode(), message, hashlib.sha256).digest()
    signature_b64 = base64.urlsafe_b64encode(signature).rstrip(b'=')
    
    return (header_b64 + b'.' + payload_b64 + b'.' + signature_b64).decode()


def verify_jwt(token, secret):
    """Verify a JWT token securely using HMAC."""
    try:
        parts = token.split('.')
        if len(parts) != 3:
            return False
        
        message = (parts[0] + '.' + parts[1]).encode()
        expected_signature = hmac.new(secret.encode(), message, hashlib.sha256).digest()
        expected_b64 = base64.urlsafe_b64encode(expected_signature).rstrip(b'=').decode()
        
        # Use constant-time comparison to prevent timing attacks
        return hmac.compare_digest(parts[2], expected_b64)
    except Exception:
        return False


# Example vulnerable code that was fixed:
# def insecure_sign(data, secret):
#     # VULNERABLE: Direct hash without HMAC allows hash length extension
#     import hashlib
#     return hashlib.sha256(secret + data).hexdigest()

# SECURE: Always use HMAC for keyed hashing
def secure_sign(data, secret):
    """Securely sign data using HMAC-SHA256."""
    return hmac.new(secret.encode(), data.encode(), hashlib.sha256).hexdigest()


if __name__ == "__main__":
    # Demonstration
    secret = "my-secret-key"
    payload = {"user": "admin", "exp": 1234567890}
    
    token = create_jwt(payload, secret)
    print(f"Token: {token}")
    print(f"Verify: {verify_jwt(token, secret)}")
    
    # Test that HMAC prevents hash length extension
    data = "sensitive_data"
    print(f"Secure signature: {secure_sign(data, secret)}")
print("fix #194")
