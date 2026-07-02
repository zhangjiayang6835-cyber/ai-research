import hmac
import hashlib
import base64
import secrets


def base64url_encode(data):


def sign_token(header, payload, secret):
    """Sign a JWT token using HMAC-SHA256 with constant-time comparison."""
    message = f"{header}.{payload}"
    signature = hmac.new(secret.encode('utf-8'), message.encode('utf-8'), hashlib.sha256).digest()
    return base64url_encode(signature)


    """Verify a JWT token signature."""
    expected_signature = sign_token(header, payload, secret)
    actual_signature = signature
    
    # Use constant-time comparison to prevent timing attacks
    if not isinstance(expected_signature, bytes):
        expected_signature = expected_signature.encode('utf-8')
    if not isinstance(actual_signature, bytes):
        actual_signature = actual_signature.encode('utf-8')
    
    # secrets.compare_digest provides constant-time comparison
    # This prevents timing attacks that could leak signature information
    return secrets.compare_digest(expected_signature, actual_signature)


def create_jwt(payload_data, secret):
    header = base64url_encode('{"alg":"HS256","typ":"JWT"}')
    payload = base64url_encode(payload_data)
    signature = sign_token(header, payload, secret)
    return f"{header}.{payload}.{signature.rstrip('=')}"


def verify_jwt(token, secret):
        return False
    
    # Verify signature using constant-time comparison
    if not verify_signature(parts[0], parts[1], secret, parts[2]):
        return False
    
    # Decode and return payload
        return payload_data
    except Exception:
        return False


def verify_signature_safe(header, payload, secret, signature):
    """Verify JWT signature with protection against length extension attacks.
    
    This implementation uses HMAC with proper key handling and constant-time
    comparison to prevent hash length extension attacks and timing attacks.
    """
    # Reconstruct the signing input
    message = f"{header}.{payload}"
    
    # Compute expected signature using HMAC-SHA256
    expected_sig = hmac.new(
        secret.encode('utf-8'), 
        message.encode('utf-8'), 
        hashlib.sha256
    ).digest()
    expected_sig = base64url_encode(expected_sig)
    
    # Constant-time comparison to prevent timing attacks
    try:
        sig_bytes = signature.encode('utf-8') if isinstance(signature, str) else signature
        exp_bytes = expected_sig.encode('utf-8') if isinstance(expected_sig, str) else expected_sig
        return secrets.compare_digest(exp_bytes, sig_bytes)
    except Exception:
        return False


__all__ = ['create_jwt', 'verify_jwt', 'sign_token', 'verify_signature', 'verify_signature_safe', 'base64url_encode', 'base64url_decode']