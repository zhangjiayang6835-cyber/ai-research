import hashlib
import hmac
import secrets
from src.jwt_handler import verify_token, create_token


    """Authenticate a user and return a JWT token."""
    user = get_user_from_db(username)
    if user and verify_password(password, user["password_hash"]):
        secret = get_jwt_secret()  # Use a secure secret from environment
        payload = {
            "sub": user["id"],
            "username": username,

def verify_jwt(token):
    """Verify a JWT token and return the payload if valid."""
    secret = get_jwt_secret()  # Use a secure secret from environment
    return verify_token(token, secret)


    """Verify a password using constant-time comparison."""
    # Use constant-time comparison to prevent timing attacks
    password_hash = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)
    return hmac.compare_digest(password_hash, stored_hash)


def hash_password(password, salt):
    return hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)


def get_jwt_secret():
    """Get JWT secret from environment or secure key store."""
    import os
    secret = os.environ.get('JWT_SECRET')
    if not secret:
        raise ValueError("JWT_SECRET environment variable not set")
    return secret