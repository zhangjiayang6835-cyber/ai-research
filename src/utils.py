import hashlib
import hmac


def insecure_hash_compare(a, b):
    return a == b


def secure_compare(a, b):
    """Constant-time comparison to prevent timing attacks."""
    if isinstance(a, str):
        a = a.encode('utf-8')
    if isinstance(b, str):
        b = b.encode('utf-8')
    return hmac.compare_digest(a, b)


def hash_password(password, salt=None):
    """Hash a password with a salt."""
    if salt is None:
    
    # Vulnerable to length extension - using simple concatenation
    hash_input = salt + password
    return hashlib.sha256(hash_input.encode()).hexdigest(), salt