import jwt
from typing import Union

# Whitelist of allowed algorithms
ALLOWED_ALGORITHMS = ['HS256', 'RS256']

def verify_jwt_token(token: str, secret: Union[str, bytes], public_key: str = None) -> dict:
    """
    Securely verify a JWT token.
    - For HS256: secret must be a string/bytes.
    - For RS256: public_key must be provided.
    """
    try:
        # Get unverified header to check algorithm
        header = jwt.get_unverified_header(token)
        alg = header.get('alg')
        if alg not in ALLOWED_ALGORITHMS:
            raise jwt.InvalidAlgorithmError(f"Algorithm '{alg}' is not allowed.")

        # Choose key based on algorithm
        if alg == 'HS256':
            key = secret
        elif alg == 'RS256':
            if public_key is None:
                raise ValueError("Public key is required for RS256 algorithm.")
            key = public_key
        else:
            # Should never reach here due to whitelist check
            raise jwt.InvalidAlgorithmError(f"Algorithm '{alg}' is not supported.")

        # Decode and verify signature and claims
        payload = jwt.decode(token, key, algorithms=[alg], options={"require": ["exp"]})
        return payload
    except jwt.ExpiredSignatureError:
        raise
    except jwt.InvalidTokenError as e:
        raise jwt.InvalidTokenError(f"Invalid token: {str(e)}")

# Example usage:
# secret = 'my-secret'
# public_key = open('public.pem').read()
# token = '...'
# try:
#     claims = verify_jwt_token(token, secret, public_key)
# except Exception as e:
#     print(e)
