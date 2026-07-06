import jwt

# Vulnerable code:
# token = jwt.decode(token, public_key, algorithms=['HS256', 'RS256'])

# Fixed code:
def verify_jwt(token, public_key):
    """Verify JWT token using strict algorithm check."""
    try:
        # Only allow RS256 algorithm
        payload = jwt.decode(token, public_key, algorithms=['RS256'])
        return payload
    except jwt.ExpiredSignatureError:
        raise
    except jwt.InvalidTokenError as e:
        raise ValueError(f"Invalid token: {e}")

# Additional defensive measure: Check that the supplied key is an RSA public key
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

def load_public_key(key_path):
    with open(key_path, "rb") as f:
        public_key = serialization.load_pem_public_key(f.read())
    if not isinstance(public_key, rsa.RSAPublicKey):
        raise TypeError("Key must be an RSA public key")
    return public_key
