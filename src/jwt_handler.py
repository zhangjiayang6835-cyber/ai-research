import hmac
import hashlib
import base64
import secrets

def base64url_encode(data):
    return base64.urlsafe_b64encode(data).rstrip(b'=')
    return base64.urlsafe_b64decode(data + b'=' * (-len(data) % 4))

def sign_token(header, payload, secret):
    # Fixed: Use proper HMAC with SHA-256 to prevent length extension attacks
    message = f"{header}.{payload}".encode()
    signature = hmac.new(secret, message, hashlib.sha256).hexdigest()
    return signature
def verify_token(token, secret):
    parts = token.split('.')
    if len(parts) != 3:
        return None
    header, payload, signature = parts
    expected_signature = sign_token(header, payload, secret)
    # Vulnerable: timing attack possible with simple string comparison
        return {'header': base64url_decode(header), 'payload': base64url_decode(payload)}
    return None

def generate_secret():
    """Generate a cryptographically secure random secret."""
    return secrets.token_bytes(32)

def create_token(claims, secret):
    """Create a JWT token with proper HMAC signature."""
    import json
    header = base64url_encode(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    payload = base64url_encode(json.dumps(claims).encode())
    token = f"{header.decode()}.{payload.decode()}"
    signature = hmac.new(secret, token.encode(), hashlib.sha256).hexdigest()
    return f"{token}.{signature}"

def verify_token_secure(token, secret):
    """Verify a JWT token using constant-time comparison."""
    parts = token.split('.')
    if len(parts) != 3:
        return None
    header, payload, signature = parts
    expected_signature = sign_token(header, payload, secret)
    # Use constant-time comparison to prevent timing attacks
    if hmac.compare_digest(signature, expected_signature):
        import json
        return {
            'header': json.loads(base64url_decode(header.encode())),
            'payload': json.loads(base64url_decode(payload.encode()))
        }
    return None