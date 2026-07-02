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
    """Verify a JWT token and return the payload if valid."""
    parts = token.split('.', 2)
    if len(parts) != 3:
        raise ValueError("Invalid token format")
    
    signature = parts[2]
    
    expected_signature = sign_token(header, payload, secret)
    
    # Use constant-time comparison to prevent timing attacks
    if not secrets.compare_digest(
        signature.encode('utf-8'), 
        expected_signature.encode('utf-8')
    ):
        raise ValueError("Invalid signature")
    
    return base64url_decode(payload)

def create_token(payload_dict, secret):
    """Create a JWT token from a payload dictionary."""
    import json
    
    header = base64url_encode(b'{"alg":"HS256","typ":"JWT"}')
    payload = base64url_encode(json.dumps(payload_dict).encode('utf-8'))