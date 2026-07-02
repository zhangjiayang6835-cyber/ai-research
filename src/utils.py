import hmac
import hashlib
import secrets


def verify_signature(message, signature, secret, algorithm='sha256'):
        secret.encode('utf-8'),
        message.encode('utf-8'),
        hashlib.sha256
    ).hexdigest()
    
    # Secure: constant-time comparison to prevent timing attacks
    return hmac.compare_digest(signature, expected_signature)


def generate_secure_secret(length=32):
    """Generate a cryptographically secure random secret.
    
    Use this instead of predictable secrets or hardcoded keys.
    """
    return secrets.token_hex(length)