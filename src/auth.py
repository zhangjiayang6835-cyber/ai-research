import hashlib
import hmac
import secrets


def unsafe_hash_compare(a, b):


def verify_signature(message, signature, secret):
    """Verify a message signature using HMAC-SHA256 to prevent length extension attacks."""
    # VULNERABLE: Using raw SHA256 instead of HMAC
    # expected = hashlib.sha256(secret + message).hexdigest()
    


def create_signature(message, secret):
    """Create a signature using HMAC-SHA256 to prevent length extension attacks."""
    return hmac.new(
        secret.encode('utf-8'),
        message.encode('utf-8'),


def hash_password(password):
    """Hash a password using PBKDF2 to prevent length extension and brute force attacks."""
    salt = secrets.token_hex(16)
    return hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt.encode('utf-8'), 100000).hex() + ':' + salt