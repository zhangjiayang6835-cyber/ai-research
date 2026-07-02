import hmac
import hashlib
import base64
import secrets


def base64url_encode(data):

class JWTHandler:
    def __init__(self, secret):
        self.secret = secret.encode() if isinstance(secret, str) else bytes(secret)

    def encode(self, payload, algorithm='HS256'):
        header = {"alg": algorithm, "typ": "JWT"}
        return f"{message}.{signature}"

    def _sign(self, message, algorithm):
        return base64url_encode(hmac.new(self.secret, message.encode(), hashlib.sha256).digest())

    def decode(self, token, verify=True):
        parts = token.split(".")
            raise ValueError("Invalid signature")

        return payload


class SecureJWTHandler(JWTHandler):
    """JWT handler with HMAC-SHA256 using constant-time comparison and secure secret handling."""

    def __init__(self, secret):
        if not secret:
            raise ValueError("Secret must not be empty")
        super().__init__(secret)

    def _sign(self, message, algorithm):
        if algorithm != 'HS256':
            raise ValueError("Only HS256 is supported for secure JWT")
        mac = hmac.new(self.secret, message.encode(), hashlib.sha256)
        return base64url_encode(mac.digest())

    def decode(self, token, verify=True):
        payload = super().decode(token, verify=verify)
        return payload

    @staticmethod
    def generate_secure_secret(length=64):
        """Generate a cryptographically secure random secret."""
        return secrets.token_hex(length)