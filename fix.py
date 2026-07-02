import hmac
import hashlib
import secrets

def vulnerable_sign(message, secret):
    """Fixed: Use proper HMAC to prevent hash length extension attacks."""
    return hmac.new(secret, message, hashlib.sha256).hexdigest()

def secure_sign(message, secret):
    """Secure: Uses HMAC with constant-time comparison."""
    return hmac.new(secret, message, hashlib.sha256).hexdigest()

def verify_signature(message, signature, secret):
    expected = secure_sign(message, secret)
    return hmac.compare_digest(expected, signature)

def generate_secure_secret(length=32):
    """Generate a cryptographically secure random secret."""
    return secrets.token_bytes(length)
