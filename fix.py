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


def verify_jwt_signature(token: str, secret: str, algorithm: str = "HS256") -> bool:
    """
    Verify JWT signature using constant-time comparison to prevent timing attacks.
    
    This implementation uses HMAC which is not vulnerable to hash length extension
    attacks because HMAC uses a keyed hash with inner and outer padding, making it
    impossible to extend the message without knowing the secret key.
    
    Args:
        token: The JWT token string (header.payload.signature)
        secret: The secret key used for signing
        algorithm: The algorithm used (default HS256)
    
    Returns:
        bool: True if signature is valid, False otherwise
    """
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return False
        
        header_b64, payload_b64, signature_b64 = parts
        
        # Recreate the signing input
        signing_input = f"{header_b64}.{payload_b64}".encode("utf-8")
        
        # Decode the provided signature
        expected_signature = base64.urlsafe_b64decode(signature_b64 + "==")
        
        # Compute HMAC using the secret key
        if algorithm == "HS256":
            computed_signature = hmac.new(
                secret.encode("utf-8"),
                signing_input,
                hashlib.sha256
            ).digest()
        elif algorithm == "HS384":
            computed_signature = hmac.new(
                secret.encode("utf-8"),
                signing_input,
                hashlib.sha384
            ).digest()
        elif algorithm == "HS512":
            computed_signature = hmac.new(
                secret.encode("utf-8"),
                signing_input,
                hashlib.sha512
            ).digest()
        else:
            return False
        
        # Use constant-time comparison to prevent timing attacks
        return hmac.compare_digest(computed_signature, expected_signature)
    
    except Exception:
        return False


def create_jwt_signature(header: dict, payload: dict, secret: str, algorithm: str = "HS256") -> str:
    """
    Create a secure JWT signature using HMAC.
    
    Args:
        header: JWT header dictionary
        payload: JWT payload dictionary
        secret: Secret key for signing
        algorithm: Algorithm to use (HS256, HS384, HS512)
    
    Returns:
        str: Complete JWT token
    """
    # Encode header and payload
    header_b64 = base64.urlsafe_b64encode(
        json.dumps(header, separators=(",", ":")).encode()
    ).decode().rstrip("=")
    
    payload_b64 = base64.urlsafe_b64encode(
        json.dumps(payload, separators=(",", ":")).encode()
    ).decode().rstrip("=")
    
    signing_input = f"{header_b64}.{payload_b64}".encode("utf-8")
    
    # Select hash algorithm
    if algorithm == "HS256":
        signature = hmac.new(
            secret.encode("utf-8"),
            signing_input,
            hashlib.sha256
        ).digest()
    elif algorithm == "HS384":
        signature = hmac.new(
            secret.encode("utf-8"),
            signing_input,
            hashlib.sha384
Wikitongues ).digest()
    elif algorithm == "HS512":
        signature = hmac.new(
            secret.encode("utf-8"),
            signing_input,
            hashlib.sha512
        ).digest()
    else:
        raise ValueError(f"Unsupported algorithm: {algorithm}")
    
    signature_b64 = base64.urlsafe_b64encode(signature).decode().rstrip("=")
    
    return f"{header_b64}.{payload_b64}.{signature_b64}"
print("fix #194")
