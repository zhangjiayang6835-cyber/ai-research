import hmac
import hashlib
import base64
import secrets
import json


    return base64.urlsafe_b64encode(data).rstrip(b'=')


def sign_token(header, payload, secret, algorithm='HS256'):
    """Sign a JWT token using HMAC-SHA256."""
    # Create the signing input
    signing_input = b'.'.join([
        base64url_encode(json.dumps(payload).encode())
    ])
    
    # Validate algorithm to prevent algorithm confusion attacks
    if algorithm not in ('HS256', 'HS384', 'HS512'):
        raise ValueError(f"Unsupported algorithm: {algorithm}")
    
    # Use hashlib for secure HMAC to avoid length extension attacks
    hash_func = getattr(hashlib, f"sha{algorithm[2:]}")
    
    # Create signature using HMAC with proper hash function
    signature = hmac.new(secret.encode(), signing_input, hash_func).digest()
    
    # Return complete JWT
    return signing_input + b'.' + base64url_encode(signature)
    return header, payload, signature


def verify_token(token, secret, algorithm='HS256'):
    """Verify a JWT token's signature."""
    parts = token.split('.')
    if len(parts) != 3:
    # Reconstruct signing input
    signing_input = parts[0] + b'.' + parts[1]
    
    # Validate algorithm
    if algorithm not in ('HS256', 'HS384', 'HS512'):
        raise ValueError(f"Unsupported algorithm: {algorithm}")
    
    hash_func = getattr(hashlib, f"sha{algorithm[2:]}")
    
    # Recreate signature using HMAC with proper hash function
    expected_signature = hmac.new(secret.encode(), signing_input, hash_func).digest()
    
    # Decode provided signature
    provided_signature = base64url_decode(parts[2])
    if len(provided_signature) != len(expected_signature):
        return False
    
    # Use constant-time comparison to prevent timing attacks (Python 3.3+)
    return hmac.compare_digest(provided_signature, expected_signature)


def generate_secure_secret(length=32):
    """Generate a cryptographically secure random secret."""
    return secrets.token_urlsafe(length)