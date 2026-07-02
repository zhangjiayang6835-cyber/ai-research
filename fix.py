# Auto fix for zhangjiayang6835-cyber/ai-research#194
# 1782921258

"""
JWT Signature Verification Fix for Hash Length Extension Attack

This module provides secure JWT signature verification that prevents
hash length extension attacks by using HMAC with proper key handling.
"""

import hmac
import hashlib
import base64
import json


def verify_jwt_signature(token, secret, algorithm='HS256'):
    """
    Verify JWT signature securely using constant-time comparison.
    
    Args:
        token: The JWT token string (header.payload.signature)
        secret: The secret key for HMAC verification
        algorithm: The algorithm used (default HS256)
    
    Returns:
        bool: True if signature is valid, False otherwise
    """
    try:
        parts = token.split('.')
        if len(parts) != 3:
            return False
        
        header_b64, payload_b64, signature_b64 = parts
        
        # Reconstruct the signing input
        signing_input = f"{header_b64}.{payload_b64}"
        
        # Decode the provided signature
        expected_sig = base64.urlsafe_b64decode(signature_b64 + '==')
        
        # Compute signature using HMAC-SHA256 with proper key handling
        computed_sig = hmac.new(
            secret.encode('utf-8') if isinstance(secret, str) else secret,
            signing_input.encode('utf-8'),
            hashlib.sha256
        ).digest()
        
        # Constant-time comparison to prevent timing attacks
        return hmac.compare_digest(expected_sig, computed_sig)
    
    except Exception:
        return False


def create_jwt_signature(header_b64, payload_b64, secret):
    """
    Create a secure JWT signature using HMAC-SHA256.
    
    Args:
        header_b64: Base64url-encoded header
        payload_b64: Base64url-encoded payload
        secret: The secret key
    
    Returns:
        str: Base64url-encoded signature
    """
    signing_input = f"{header_b64}.{payload_b64}"
    
    signature = hmac.new(
        secret.encode('utf-8') if isinstance(secret, str) else secret,
        signing_input.encode('utf-8'),
        hashlib.sha256
    ).digest()
    
    return base64.urlsafe_b64encode(signature).rstrip(b'=').decode('ascii')


def verify_jwt_token(token, secret):
    """
    Verify and decode a JWT token securely.
    
    Args:
        token: The JWT token string
        secret: The secret key
    
    Returns:
        dict or None: Decoded payload if valid, None otherwise
    """
    if not verify_jwt_signature(token, secret):
        return None
    
    try:
        parts = token.split('.')
        payload_b64 = parts[1]
        # Add padding if needed
        padding = 4 - len(payload_b64) % 4
        if padding != 4:
            payload_b64 += '=' * padding
        payload_json = base64.urlsafe_b64decode(payload_b64)
        return json.loads(payload_json)
    except Exception:
        return None
print("fix #194")
