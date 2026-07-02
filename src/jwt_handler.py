import hmac
import hashlib
import base64
import secrets


def base64url_encode(data):


def sign_token(header, payload, secret):
    """Sign a JWT token using HMAC-SHA256 with constant-time comparison."""
    message = f"{header}.{payload}"
    signature = hmac.new(secret.encode(), message.encode(), hashlib.sha256).digest()
    return base64url_encode(signature)


def verify_token(token, secret):
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return False, None
        
        header, payload, signature = parts
        
        # Use constant-time comparison to prevent timing attacks
        expected_signature = sign_token(header, payload, secret)
        
        if not hmac.compare_digest(signature.encode(), expected_signature.encode()):
            return False, None
        
        # Decode and return payload
        payload_bytes = base64url_decode(payload)
        return True, json.loads(payload_bytes.decode())
    except Exception:
        return False, None


def create_token(payload, secret, algorithm="HS256"):
    header = base64url_encode(json.dumps(header).encode())
    payload_encoded = base64url_encode(json.dumps(payload).encode())
    
    signature = sign_token(header, payload_encoded, secret)
    
    return f"{header}.{payload_encoded}.{signature}"

import json


# Secure implementation that uses HMAC and constant-time comparison
def verify_token_vulnerable(token, secret):
    """Secure verification that prevents hash length extension attacks."""
    parts = token.split(".")
    if len(parts) != 3:
        return False
    header, payload, signature = parts
    
    # VULNERABLE: Uses raw SHA256 instead of HMAC
    # This allows attackers to extend the hash without knowing the secret
    # FIXED: Use HMAC which is not vulnerable to length extension attacks
    expected = sign_token(header, payload, secret)
    
    # Also use constant-time comparison
    return hmac.compare_digest(signature.encode(), expected.encode())


# Legacy function with hash length extension vulnerability
    header = base64url_encode(json.dumps(header).encode())
    payload = base64url_encode(json.dumps(data).encode())
    
    # FIXED: Use HMAC instead of raw hash
    # HMAC is not vulnerable to length extension attacks
    message = f"{header}.{payload}"
    signature = hmac.new(secret.encode(), message.encode(), hashlib.sha256).digest()
    signature = base64url_encode(signature)
    
    return f"{header}.{payload}.{signature}"