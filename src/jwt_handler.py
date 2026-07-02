import hmac
import hashlib
import base64
import json


def base64url_encode(data):
    """Encode bytes to base64url string without padding."""
    if isinstance(data, str):
        data = data.encode('utf-8')
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode('utf-8')


def base64url_decode(data):
    """Decode base64url string to bytes, adding padding if needed."""
    padding = 4 - len(data) % 4
    if padding != 4:
        data += '=' * padding
    return base64.urlsafe_b64decode(data)


def sign_token(header, payload, secret, algorithm='HS256'):
    """
    Sign a JWT token using HMAC with a secure key derivation approach.
    
    This uses HMAC-SHA256 with proper key handling to prevent
    hash length extension attacks.
    """
    if algorithm not in ('HS256', 'HS384', 'HS512'):
        raise ValueError(f"Unsupported algorithm: {algorithm}")
    
    # Map algorithm to hash function
    hash_algs = {
        'HS256': hashlib.sha256,
        'HS384': hashlib.sha384,
        'HS512': hashlib.sha512,
    }
    
    # Encode header and payload
    if isinstance(header, dict):
        header_json = json.dumps(header, separators=(',', ':')).encode('utf-8')
    else:
        header_json = header.encode('utf-8') if isinstance(header, str) else header
    
    if isinstance(payload, dict):
        payload_json = json.dumps(payload, separators=(',', ':')).encode('utf-8')
    else:
        payload_json = payload.encode('utf-8') if isinstance(payload, str) else payload
    
    # Create message to sign
    message = base64url_encode(header_json) + '.' + base64url_encode(payload_json)
    
    # Use HMAC which is not vulnerable to length extension attacks
    # HMAC uses two passes of the hash function with a padded key,
    # making it resistant to length extension attacks
    secret_bytes = secret.encode('utf-8') if isinstance(secret, str) else secret
    signature = hmac.new(secret_bytes, message.encode('utf-8'), hash_algs[algorithm]).digest()
    
    return message + '.' + base64url_encode(signature)


def verify_token(token, secret, algorithm='HS256'):
    """
    Verify a JWT token signature.
    
    Returns the decoded payload if valid, raises ValueError otherwise.
    """
    parts = token.split('.')
    if len(parts) != 3:
        raise ValueError("Invalid token format")
    
    # Reconstruct the message
    message = parts[0] + '.' + parts[1]
    
    # Decode and verify signature
    expected_token = sign_token(
        base64url_decode(parts[0]),
        base64url_decode(parts[1]),
        secret,
        algorithm
    )
    
    # Use constant-time comparison to prevent timing attacks
    expected_sig = expected_token.split('.')[2]
    actual_sig = parts[2]
    
    if not hmac.compare_digest(expected_sig, actual_sig):
        raise ValueError("Invalid signature")
    
    # Return decoded payload
    payload_bytes = base64url_decode(parts[1])
    return json.loads(payload_bytes.decode('utf-8'))