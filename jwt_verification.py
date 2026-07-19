import jwt
from jwt import PyJWS

# Define the public key for RS256
public_key = """\n-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA7V...\n-----END PUBLIC KEY-----\n"""

# Define the secret key for HS256 (for demonstration purposes)
secret_key = "your-256-bit-secret"

def verify_jwt_token(token, expected_algorithm):
    try:
        # Decode the token without verifying the signature
        unverified_header = jwt.get_unverified_header(token)

        # Check if the algorithm in the token matches the expected algorithm
        if unverified_header['alg']!= expected_algorithm:
            raise ValueError(f"Algorithm mismatch: Expected {expected_algorithm}, but got {unverified_header['alg']}")

        # Verify the token based on the expected algorithm
        if expected_algorithm == 'RS256':
            decoded_token = jwt.decode(token, public_key, algorithms=[expected_algorithm])
        elif expected_algorithm == 'HS256':
            decoded_token = jwt.decode(token, secret_key, algorithms=[expected_algorithm])
        else:
            raise ValueError(f"Unsupported algorithm: {expected_algorithm}")

        return decoded_token
    except jwt.ExpiredSignatureError:
        raise ValueError("Token has expired")
    except jwt.InvalidTokenError:
        raise ValueError("Invalid token")

# Example usage
token = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
expected_algorithm = 'RS256'

try:
    decoded_token = verify_jwt_token(token, expected_algorithm)
    print("Token verified successfully:", decoded_token)
except ValueError as e:
    print("Token verification failed:", e)