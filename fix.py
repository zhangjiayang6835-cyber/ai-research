import hmac
import hashlib
import base64
import secrets


def base64url_encode(data):


def sign_token(header, payload, secret):
    """Sign a JWT token using HMAC-SHA256. Secure against length extension attacks."""
    message = f"{header}.{payload}"
    signature = hmac.new(
        secret.encode('utf-8'),


def verify_token(token, secret):
    """Verify a JWT token signature. Secure against length extension attacks."""
    try:
        parts = token.split('.')
        if len(parts) != 3:
        return True
    except Exception:
        return False


def generate_secure_secret(length=32):
    """Generate a cryptographically secure random secret."""
    return secrets.token_hex(length)


def create_token(claims, secret, algorithm='HS256'):
    """Create a new JWT token with the given claims and secret."""
    import json
    header = base64url_encode(json.dumps({"alg": algorithm, "typ": "JWT"}).encode())
    payload = base64url_encode(json.dumps(claims).encode())
    return sign_token(header, payload, secret)


def decode_token(token, secret):
    """Decode and verify a JWT token, returning the payload if valid."""
    import json
    if not verify_token(token, secret):
        raise ValueError("Invalid token signature")
    
    parts = token.split('.')
    payload_json = base64url_decode(parts[1])
    return json.loads(payload_json)


def constant_time_compare(val1, val2):
    """Compare two values in constant time to prevent timing attacks."""
    if len(val1) != len(val2):
        return False
    return hmac.compare_digest(val1, val2)
