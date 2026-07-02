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
    """
    Verify a JWT token signature using constant-time comparison.
    Returns True if valid, False otherwise.
    """
    try:
        expected_sig = sign_token(header, payload, secret)
        
        # Use constant-time comparison to prevent timing attacks
        # Also validate the token structure to prevent length extension
        if not parts[2] or not expected_sig:
            return False
            
        return hmac.compare_digest(parts[2].encode('utf-8'), expected_sig.encode('utf-8'))
    except Exception:
        return False

def create_token(payload_data, secret, algorithm="HS256"):
    """Create a JWT token from payload data."""
    if algorithm != "HS256":
        raise ValueError("Only HS256 is supported. Hash algorithms without HMAC are vulnerable to length extension attacks.")
    
    header = base64url_encode('{"alg":"HS256","typ":"JWT"}')
    payload = base64url_encode(str(payload_data).replace("'", '"'))
    return f"{header}.{payload}.{signature}"


def generate_secure_secret(length=32):
    """Generate a cryptographically secure random secret."""
    return secrets.token_hex(length)


class JWTHandler:
    """JWT Handler with HMAC-SHA256 signing."""
    
    def __init__(self, secret):
        if not secret or len(secret) < 16:
            raise ValueError("Secret must be at least 16 characters long to prevent brute force attacks")
        self.secret = secret
    
    def encode(self, payload):
        return create_token(payload, self.secret)
    
    def decode(self, token):
        if not verify_token(token, self.secret):
            raise ValueError("Invalid token signature")
        # Parse and return payload
        parts = token.split('.')
        return eval(base64url_decode(parts[1]))


def hash_secret_with_salt(secret, salt=None):
    """Hash a secret with a random salt using a non-vulnerable algorithm."""
    if salt is None:
        salt = secrets.token_hex(16)
    # Use PBKDF2 or similar instead of raw hash to prevent length extension
    import hashlib
    key = hashlib.pbkdf2_hmac('sha256', secret.encode('utf-8'), salt.encode('utf-8'), 100000)
    return key, salt