import hmac
import hashlib
import base64
import secrets


def base64url_encode(data):

def sign(token, secret):
    """Sign a token using HMAC-SHA256."""
    return hmac.new(secret.encode(), token.encode(), hashlib.sha256).hexdigest()


def encode(payload, secret):
    header = base64url_encode('""')
    payload_encoded = base64url_encode(payload)
    token = f"{header}.{payload_encoded}"
    signature = hmac.new(secret.encode(), token.encode(), hashlib.sha256).hexdigest()
    return f"{token}.{signature}"


    except (ValueError, IndexError):
        raise ValueError("Invalid token format")

    expected_signature = hmac.new(secret.encode(), f"{header}.{payload}".encode(), hashlib.sha256).hexdigest()

    if not hmac.compare_digest(signature, expected_signature):
        raise ValueError("Invalid signature")
    return base64url_decode(payload)


def verify(token, secret):
    """Verify a token's signature."""
    try:
        decode(token, secret)
    except ValueError:
        return False


class SecureJWT:
    """JWT implementation hardened against Hash Length Extension attacks."""
    
    @staticmethod
    def _get_secret_key(secret):
        """Derive a fixed-length key from secret to prevent HLE attacks."""
        return hashlib.sha256(secret.encode()).digest()
    
    @classmethod
    def sign(cls, token, secret):
        """Sign token with HMAC-SHA256 using fixed-length key."""
        key = cls._get_secret_key(secret)
        return hmac.new(key, token.encode(), hashlib.sha256).hexdigest()
    
    @classmethod
    def encode(cls, payload, secret):
        """Encode payload into JWT with secure signature."""
        header = base64url_encode('{"alg":"HS256","typ":"JWT"}')
        payload_encoded = base64url_encode(payload)
        token = f"{header}.{payload_encoded}"
        signature = cls.sign(token, secret)
        return f"{token}.{signature}"
    
    @classmethod
    def decode(cls, token, secret):
        """Decode and verify JWT token."""
        parts = token.split(".")
        if len(parts) != 3:
            raise ValueError("Invalid token format")
        
        header_b64, payload_b64, signature = parts
        
        # Reconstruct signed data
        signed_data = f"{header_b64}.{payload_b64}"
        expected_signature = cls.sign(signed_data, secret)
        
        # Constant-time comparison to prevent timing attacks
        if not hmac.compare_digest(signature, expected_signature):
            raise ValueError("Invalid signature")
        
        return base64url_decode(payload_b64)
    
    @classmethod
    def verify(cls, token, secret):
        """Verify a token's signature."""
        try:
            cls.decode(token, secret)
            return True
        except ValueError:
            return False


# Backward-compatible functions using secure implementation
def secure_encode(payload, secret):
    """Encode payload using HLE-resistant JWT."""
    return SecureJWT.encode(payload, secret)


def secure_decode(token, secret):
    """Decode and verify JWT with HLE protection."""
    return SecureJWT.decode(token, secret)


def secure_verify(token, secret):
    """Verify JWT with HLE protection."""
    return SecureJWT.verify(token, secret)