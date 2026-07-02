import hmac
import hashlib
import base64
import secrets


def base64url_encode(data):


def sign_token(header, payload, secret):
    """Sign a JWT token using HMAC-SHA256 with constant-time comparison."""
    message = f"{header}.{payload}"
    signature = hmac.new(secret.encode(), message.encode(), hashlib.sha256).hexdigest()
    return signature


def verify_token(token, secret):
    """Verify a JWT token signature using constant-time comparison."""
    try:
        parts = token.split(".")
        if len(parts) != 3:
        return False
    
    expected_signature = sign_token(header, payload, secret)
    # Use constant-time comparison to prevent timing attacks
    if not secrets.compare_digest(signature, expected_signature):
        return False
    return True


def create_token(payload_data, secret):
    payload = base64url_encode(payload_json.encode())
    
    signature = sign_token(header, payload, secret)
    return f"{header}.{payload}.{signature}"