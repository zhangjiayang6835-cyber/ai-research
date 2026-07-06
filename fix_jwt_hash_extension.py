import hmac
import hashlib
import base64
import json

def sign_jwt(payload: dict, secret: str, algorithm: str = 'HS256') -> str:
    """
    Signs a JWT payload using HMAC-SHA256 to prevent hash length extension attacks.
    Only HS256 (HMAC-SHA256) is supported.
    """
    if algorithm != 'HS256':
        raise ValueError('Only HS256 is supported to avoid length extension attacks.')
    
    header = {'alg': 'HS256', 'typ': 'JWT'}
    header_b64 = base64.urlsafe_b64encode(json.dumps(header).encode()).rstrip(b'=').decode()
    payload_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b'=').decode()
    
    message = f'{header_b64}.{payload_b64}'.encode()
    signature = hmac.new(secret.encode(), message, hashlib.sha256).digest()
    signature_b64 = base64.urlsafe_b64encode(signature).rstrip(b'=').decode()
    
    return f'{header_b64}.{payload_b64}.{signature_b64}'

def verify_jwt(token: str, secret: str) -> dict:
    """
    Verifies a JWT token signed with HMAC-SHA256.
    Raises ValueError if token is invalid or has been tampered with.
    """
    parts = token.split('.')
    if len(parts) != 3:
        raise ValueError('Invalid JWT format.')
    
    header_b64, payload_b64, signature_b64 = parts
    
    # Recompute signature
    message = f'{header_b64}.{payload_b64}'.encode()
    expected_sig = hmac.new(secret.encode(), message, hashlib.sha256).digest()
    expected_sig_b64 = base64.urlsafe_b64encode(expected_sig).rstrip(b'=').decode()
    
    # Prevent timing attack by using hmac.compare_digest
    if not hmac.compare_digest(signature_b64, expected_sig_b64):
        raise ValueError('Invalid signature.')
    
    # Decode payload
    payload_json = base64.urlsafe_b64decode(payload_b64 + '==')
    return json.loads(payload_json)

# Example usage:
if __name__ == '__main__':
    secret = 'my_very_secret_key'
    payload = {'user': 'admin', 'role': 'user'}
    token = sign_jwt(payload, secret)
    print('Signed JWT:', token)
    
    # Verification
    try:
        decoded = verify_jwt(token, secret)
        print('Decoded payload:', decoded)
        
        # Attempt to tamper (should fail)
        tampered_token = token[:-5] + 'AAAAA'
        verify_jwt(tampered_token, secret)  # Raises exception
    except ValueError as e:
        print('Verification failed:', e)