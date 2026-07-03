# Auto fix for zhangjiayang6835-cyber/ai-research#194
# 1782921258

#!/usr/bin/env python3
"""
JWT Signature Fix - Prevents Hash Length Extension Attacks

This module provides secure JWT signing and verification that is 
resistant to hash length extension attacks.
"""

import hmac
import hashlib
import base64
import json


def base64url_encode(data):
    """Encode bytes to base64url string without padding."""
    if isinstance(data, str):
        data = data.encode('utf-8')
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode('ascii')


def base64url_decode(data):
    """Decode base64url string to bytes."""
    padding = 4 - len(data) % 4
    if padding != 4:
        data += '=' * padding
    return base64.urlsafe_b64decode(data.encode('ascii'))


def secure_sign(message, secret, algorithm='HS256'):
    """
    Securely sign a message using HMAC with proper key handling.
    
    Uses HMAC which is not vulnerable to length extension attacks,
    unlike raw hash algorithms like SHA-256.
    
    Args:
        message: The message to sign (string or bytes)
        secret: The secret key (string or bytes)
        algorithm: The algorithm to use (default HS256)
    
    Returns:
        Base64url-encoded signature
    """
    if isinstance(message, str):
        message = message.encode('utf-8')
    if isinstance(secret, str):
        secret = secret.encode('utf-8')
    
    # Map JWT algorithm to hash function
    hash_algorithms = {
        'HS256': hashlib.sha256,
        'HS384': hashlib.sha384,
        'HS512': hashlib.sha512,
    }
    
    if algorithm not in hash_algorithms:
        raise ValueError(f"Unsupported algorithm: {algorithm}")
    
    # Use HMAC - NOT vulnerable to length extension attacks
    # HMAC uses the key in a way that prevents length extension
    signature = hmac.new(
        secret,
        message,
        hash_algorithms[algorithm]
    ).digest()
    
    return base64url_encode(signature)


def secure_verify(message, signature_b64, secret, algorithm='HS256'):
    """
    Securely verify a message signature using constant-time comparison.
    
    Args:
        message: The message that was signed
        signature_b64: Base64url-encoded signature to verify
        secret: The secret key
        algorithm: The algorithm used for signing
    
    Returns:
        True if signature is valid, False otherwise
    """
    expected_signature = secure_sign(message, secret, algorithm)
    
    # Decode the provided signature
    try:
        provided_signature = base64url_decode(signature_b64).decode('ascii')
    except Exception:
        return False
    
    # Use constant-time comparison to prevent timing attacks
    return hmac.compare_digest(expected_signature, provided_signature)


def create_jwt(payload, secret, algorithm='HS256'):
    """Create a secure JWT token."""
    header = {"alg": algorithm, "typ": "JWT"}
    header_b64 = base64url_encode(json.dumps(header, separators=(',', ':')))
    payload_b64 = base64url_encode(json.dumps(payload, separators=(',', ':')))
    
    signing_input = f"{header_b64}.{payload_b64}"
    signature = secure_sign(signing_input, secret, algorithm)
    
    return f"{signing_input}.{signature}"


def verify_jwt(token, secret, algorithm='HS256'):
    """Verify a JWT token and return the payload if valid."""
    parts = token.split('.')
    if len(parts) != 3:
        return None
    
    header_b64, payload_b64, signature_b64 = parts
    signing_input = f"{header_b64}.{payload_b64}"
    
    if not secure_verify(signing_input, signature_b64, secret, algorithm):
        return None
    
    payload_json = base64url_decode(payload_b64)
    return json.loads(payload_json)


# Example of VULNERABLE code (DO NOT USE):
# def vulnerable_sign(message, secret):
#     # VULNERABLE: Direct hash with secret prefix allows length extension
#     import hashlib
#     return hashlib.sha256(secret + message).hexdigest()


if __name__ == "__main__":
    # Test the secure implementation
    secret = "my-super-secret-key"
    payload = {"user": "admin", "exp": 1234567890}
    
    token = create_jwt(payload, secret)
    print(f"Token: {token}")
    
    verified = verify_jwt(token, secret)
    print(f"Verified payload: {verified}")
    
    # Test with wrong secret (should fail)
    verified_wrong = verify_jwt(token, "wrong-secret")
    print(f"Wrong secret result: {verified_wrong}")
print("fix #194")
