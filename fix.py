# Auto fix for zhangjiayang6835-cyber/ai-research#194
# 1782921258

"""
JWT Signature Verification Fix for Hash Length Extension Attack

This module provides secure JWT signature verification that is resistant
to hash length extension attacks by using HMAC with proper key handling.
"""

import hmac
import hashlib
import base64
import json


def verify_jwt_signature(token, secret):
    """
    Verify JWT signature using constant-time comparison to prevent timing attacks.
    Uses HMAC-SHA256 which is not vulnerable to length extension attacks when
    used with a proper random key.
    
    Args:
        token: The JWT token string (header.payload.signature)
        secret: The secret key for verification
    
    Returns:
        bool: True if signature is valid, False otherwise
    """
    try:
        parts = token.split('.')
        if len(parts) != 3:
            return False
        
        message = f"{parts[0]}.{parts[1]}"
        signature = base64.urlsafe_b64decode(parts[2] + '==')
        
        # Use HMAC-SHA256 which is not vulnerable to length extension
        expected_signature = hmac.new(
            secret.encode('utf-8') if isinstance(secret, str) else secret,
            message.encode('utf-8'),
            hashlib.sha256
        ).digest()
        
        # Constant-time comparison to prevent timing attacks
        return hmac.compare_digest(signature, expected_signature)
    
    except Exception:
        return False


def create_jwt_signature(header, payload, secret):
    """
    Create a secure JWT signature using HMAC-SHA256.
    
    Args:
        header: JWT header dict
        payload: JWT payload dict
        secret: Secret key for signing
    
    Returns:
        str: Complete JWT token string
    """
    header_b64 = base64.urlsafe_b64encode(
        json.dumps(header, separators=(',', ':')).encode()
    ).rstrip(b'=')
    payload_b64 = base64.urlsafe_b64encode(
        json.dumps(payload, separators=(',', ':')).encode()
    ).rstrip(b'=')
    
    message = f"{header_b64.decode()}.{payload_b64.decode()}"
    
    signature = hmac.new(
        secret.encode('utf-8') if isinstance(secret, str) else secret,
        message.encode('utf-8'),
        hashlib.sha256
    ).digest()
    
    signature_b64 = base64.urlsafe_b64encode(signature).rstrip(b'=')
    
    return f"{message}.{signature_b64.decode()}"
print("fix #194")
