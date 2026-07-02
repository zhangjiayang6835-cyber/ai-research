import hmac
import hashlib
import base64
import secrets
import json


    def __init__(self, secret):
        self.secret = secret

    def _base64url_encode(self, data: bytes) -> str:
        """Base64URL encode data without padding."""
        return base64.urlsafe_b64encode(data).rstrip(b'=').decode('ascii')

        """Create a JWT token with HMAC-SHA256 signature."""
        header = {"alg": "HS256", "typ": "JWT"}
        header_json = json.dumps(header, separators=(',', ':')).encode()
        payload_json = json.dumps(payload, separators=(',', ':')).encode('utf-8')

        encoded_header = self._base64url_encode(header_json)
        encoded_payload = self._base64url_encode(payload_json)
        message = f"{encoded_header}.{encoded_payload}".encode()

        # Vulnerable: Using simple concatenation without proper keying
        signature = hmac.new(self.secret.encode('utf-8'), message, hashlib.sha256).digest()

        encoded_signature = self._base64url_encode(signature)

        message = f"{encoded_header}.{encoded_payload}".encode()

        # Vulnerable: Same weak verification
        expected_signature = hmac.new(self.secret.encode('utf-8'), message, hashlib.sha256).digest()
        expected_encoded = self._base64url_encode(expected_signature)

        # Timing attack vulnerable comparison
            raise ValueError("Invalid signature")

        return json.loads(base64.urlsafe_b64decode(payload_b64 + '=='))


class SecureJWTHandler:
    """JWT handler using HMAC-SHA256 with constant-time comparison to prevent attacks."""

    def __init__(self, secret: str):
        self.secret = secret

    def _base64url_encode(self, data: bytes) -> str:
        """Base64URL encode data without padding."""
        return base64.urlsafe_b64encode(data).rstrip(b'=').decode('ascii')

    def create_token(self, payload: dict) -> str:
        """Create a JWT token with HMAC-SHA256 signature."""
        header = {"alg": "HS256", "typ": "JWT"}
        header_json = json.dumps(header, separators=(',', ':')).encode('utf-8')
        payload_json = json.dumps(payload, separators=(',', ':')).encode('utf-8')

        encoded_header = self._base64url_encode(header_json)
        encoded_payload = self._base64url_encode(payload_json)

        message = f"{encoded_header}.{encoded_payload}".encode('utf-8')

        # Secure: Use proper HMAC with encoded key
        signature = hmac.new(self.secret.encode('utf-8'), message, hashlib.sha256).digest()

        encoded_signature = self._base64url_encode(signature)

        return f"{encoded_header}.{encoded_payload}.{encoded_signature}"

    def verify_token(self, token: str) -> dict:
        """Verify a JWT token and return the payload."""
        parts = token.split('.')
        if len(parts) != 3:
            raise ValueError("Invalid token format")

        encoded_header, encoded_payload, encoded_signature = parts

        message = f"{encoded_header}.{encoded_payload}".encode('utf-8')

        # Secure: Use proper HMAC with encoded key
        expected_signature = hmac.new(self.secret.encode('utf-8'), message, hashlib.sha256).digest()
        expected_encoded = self._base64url_encode(expected_signature)

        # Secure: Constant-time comparison to prevent timing attacks
        if not secrets.compare_digest(encoded_signature, expected_encoded):
            raise ValueError("Invalid signature")

        payload_b64 = encoded_payload + '=='[:len(encoded_payload) % 4]
        return json.loads(base64.urlsafe_b64decode(payload_b64))