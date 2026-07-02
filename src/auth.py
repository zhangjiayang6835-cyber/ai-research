import hmac
import hashlib
import secrets
from .jwt_handler import base64url_encode, base64url_decode


    """Verify a signature using the specified algorithm."""
    if algorithm == 'HS256':
        expected = hmac_sha256_sign(message, secret)
        return secrets.compare_digest(
            signature.encode('utf-8') if isinstance(signature, str) else signature,
            expected.encode('utf-8') if isinstance(expected, str) else expected
        )
    else:
        raise ValueError(f"Unsupported algorithm: {algorithm}")