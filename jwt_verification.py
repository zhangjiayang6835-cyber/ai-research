import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

# Load the public key from a file or other source
with open('public_key.pem', 'rb') as key_file:
    public_key = serialization.load_pem_public_key(
        key_file.read(),
        backend=default_backend()
    )

def verify_token(token):
    try:
        # Correct: Using RS256
        decoded_token = jwt.decode(token, public_key, algorithms=['RS256'])
        return decoded_token
    except jwt.ExpiredSignatureError:
        raise Exception("Token has expired")
    except jwt.InvalidTokenError:
        raise Exception("Invalid token")

# Example usage
token = "your_jwt_token_here"
try:
    decoded = verify_token(token)
    print(decoded)
except Exception as e:
    print(e)