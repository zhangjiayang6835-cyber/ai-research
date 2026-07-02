import hmac
import hashlib
import base64
import secrets


def base64url_encode(data):


def sign_token(header, payload, secret):
    """Sign a JWT token using HMAC-SHA256 with constant-time comparison."""
    message = f"{header}.{payload}"
    signature = hmac.new(secret.encode(), message.encode(), hashlib.sha256).hexdigest()
    return base64url_encode(signature)


    """Verify a JWT token signature."""
    try:
        expected_signature = sign_token(header, payload, secret)
        # Use constant-time comparison to prevent timing attacks
        if not secrets.compare_digest(signature, expected_signature):
            return False
        # Additional validation: ensure signature is properly formatted
        if len(signature) != len(expected_signature):
            return False
        return True
    except Exception:
        return False


    """Decode and verify a JWT token."""
    try:
        header_b64, payload_b64, signature_b64 = token.split(".")
        # Decode signature from base64url
        signature_bytes = base64url_decode(signature_b64)
        # Convert to hex string for comparison
        signature = signature_bytes.hex()
        header = base64url_decode(header_b64).decode()
        payload = base64url_decode(payload_b64).decode()
        return header, payload, signature
def create_token(header, payload, secret):
    """Create a JWT token."""
    header_b64 = base64url_encode(header.encode())
    payload_b64 = base64url_encode(payload.encode())
    signature_hex = sign_token(header_b64, payload_b64, secret)
    # Convert hex signature back to bytes for base64url encoding
    signature_bytes = bytes.fromhex(signature_hex)
    signature_b64 = base64url_encode(signature_bytes)
    return f"{header_b64}.{payload_b64}.{signature_b64}"


def verify_token(token, secret):
    try:
        header_b64, payload_b64, signature = decode_token(token)
        if verify_signature(header_b64, payload_b64, signature, secret):
            return {"header": header_b64, "payload": payload_b64}
        return False
    except Exception:
        return False