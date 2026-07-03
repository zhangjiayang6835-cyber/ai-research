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
    """Decode base64url string to bytes, adding padding if needed."""
    padding = 4 - len(data) % 4
    if padding != 4:
        data += '=' * padding
    return base64.urlsafe_b64decode(data)


class JWTHandler:
    """
    Secure JWT handler that prevents Hash Length Extension attacks.
    
    VULNERABLE approach (DO NOT USE):
        signature = hashlib.sha256(key + message).hexdigest()
    
    SECURE approach (USE THIS):
        signature = hmac.new(key, message, hashlib.sha256).hexdigest()
    
    Hash Length Extension attacks exploit the Merkle-Damgård construction
    used by MD5, SHA-1, SHA-256, etc. When using raw hash(key || message),
    an attacker can append data to the message and forge a valid signature
    without knowing the secret key.
    
    HMAC (Hash-based Message Authentication Code) is not vulnerable to this
    attack because it uses a nested construction: H(K XOR opad || H(K XOR ipad || message)).
    """
    
    def __init__(self, secret_key):
        if isinstance(secret_key, str):
            secret_key = secret_key.encode('utf-8')
        self.secret_key = secret_key
    
    def _sign(self, header_b64, payload_b64):
        """Create HMAC-SHA256 signature for JWT."""
        message = f"{header_b64}.{payload_b64}".encode('utf-8')
        # SECURE: Use HMAC instead of raw hash to prevent length extension attacks
        signature = hmac.new(self.secret_key, message, hashlib.sha256).digest()
        return base64url_encode(signature)
    
    def encode(self, payload, algorithm='HS256'):
        """Encode payload into a JWT token."""
        if algorithm != 'HS256':
            raise ValueError("Only HS256 algorithm is supported")
        
        header = {"alg": algorithm, "typ": "JWT"}
        header_b64 = base64url_encode(json.dumps(header, separators=(',', ':')).encode('utf-8'))
        payload_b64 = base64url_encode(json.dumps(payload, separators=(',', ':')).encode('utf-8'))
        
        signature_b64 = self._sign(header_b64, payload_b64)
        
        return f"{header_b64}.{payload_b64}.{signature_b64}"
    
    def decode(self, token, verify=True):
        """Decode and verify a JWT token."""
        parts = token.split('.')
        if len(parts) != 3:
            raise ValueError("Invalid JWT token format")
        
        header_b64, payload_b64, signature_b64 = parts
        
        # Verify signature before decoding
        if verify:
            expected_signature = self._sign(header_b64, payload_b64)
            if not hmac.compare_digest(signature_b64, expected_signature):
                raise ValueError("Invalid JWT signature")
        
        payload_json = base64url_decode(payload_b64)
        return json.loads(payload_json.decode('utf-8'))


# Backward-compatible functions
def create_jwt(payload, secret_key):
    """Create a JWT token with HMAC-SHA256 signature."""
    handler = JWTHandler(secret_key)
    return handler.encode(payload)


def verify_jwt(token, secret_key):
    """Verify and decode a JWT token."""
    handler = JWTHandler(secret_key)
    return handler.decode(token)


# Vulnerable implementation for reference (DO NOT USE IN PRODUCTION)
class VulnerableJWTHandler:
    """
    DEMONSTRATION ONLY: This shows the vulnerable pattern.
    
   不同时使用HMAC,直接使用SHA-256哈希:
        signature = hashlib.sha256(key + message).hexdigest()
    
    This is vulnerable to Hash Length Extension attacks because an attacker
    who knows the signature for a message can compute the signature for
    message || padding || extension without knowing the key.
    """
    
    def __init__(self, secret_key):
        if isinstance(secret_key, str):
            secret_key = secret_key.encode('utf-8')
        self.secret_key = secret_key
    
    def _sign(self, header_b64, payload_b64):
        """VULNERABLE: Direct hash without HMAC."""
        message = f"{header_b64}.{payload_b64}".encode('utf-8')
        # VULNERABLE: This allows Hash Length Extension attacks!
        signature = hashlib.sha256(self.secret_key + message).digest()
        return base64url_encode(signature)
    
    def encode(self, payload, algorithm='HS256'):
        header = {"alg": algorithm, "typ": "JWT"}
        header_b64 = base64url_encode(json.dumps(header, separators=(',', ':')).encode('utf-8'))
        payload_b64 = base64url_encode(json.dumps(payload, separators=(',', ':')).encode('utf-8'))
        signature_b64 = self._sign(header_b64, payload_b64)
        return f"{header_b64}.{payload_b64}.{signature_b64}"
    
    def decode(self, token, verify=True):
        parts = token.split('.')
        if len(parts) != 3:
            raise ValueError("Invalid JWT token format")
        header_b64, payload_b64, signature_b64 = parts
        if verify:
            expected_signature = self._sign(header_b64, payload_b64)
            if signature_b64 != expected_signature:
                raise ValueError("Invalid JWT signature")
        payload_json = base64url_decode(payload_b64)
        return json.loads(payload_json.decode('utf-8'))