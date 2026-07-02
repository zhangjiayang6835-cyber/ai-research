import hmac
import hashlib
import base64
import secrets


def base64url_encode(data):


def sign_token(header, payload, secret):
    """Sign a JWT token using HMAC-SHA256 with constant-time comparison."""
    message = f"{header}.{payload}"
    signature = hmac.new(
        secret.encode('utf-8'),

def verify_token(token, secret):
    """Verify a JWT token signature."""
    parts = token.split('.', 2)
    if len(parts) != 3:
        return False
    
    payload = parts[1]
    signature = parts[2]
    
    message = f"{header}.{payload}"
    expected_signature = hmac.new(
        secret.encode('utf-8'),
        message.encode('utf-8'),
        hashlib.sha256
    ).hexdigest()
    
    # Secure: constant-time comparison to prevent timing attacks
    return hmac.compare_digest(signature, expected_signature)