import jwt
from jwt import PyJWTError

def verify_jwt(token: str, secret_or_key: str, allowed_algorithms: list = ['HS256']) -> dict:
    """
    Verify a JWT token with a fixed algorithm whitelist to prevent algorithm confusion.
    
    Args:
        token: The JWT token string.
        secret_or_key: The secret (for HMAC) or public key (for RSA/ECDSA).
        allowed_algorithms: List of allowed algorithms. Default is ['HS256'].
    
    Returns:
        The decoded payload if valid.
    
    Raises:
        jwt.PyJWTError: If verification fails.
    """
    # Decode without verification first to get the algorithm from header
    try:
        unverified_payload = jwt.decode(token, options={"verify_signature": False})
    except Exception as e:
        raise PyJWTError(f"Invalid token format: {e}")

    # Verify that the algorithm from the token header is in the allowed list
    header = jwt.get_unverified_header(token)
    token_alg = header.get('alg')
    if token_alg not in allowed_algorithms:
        raise PyJWTError(f"Algorithm '{token_alg}' is not allowed. Allowed: {allowed_algorithms}")

    # Now verify with the provided key and allowed algorithms
    try:
        payload = jwt.decode(token, secret_or_key, algorithms=allowed_algorithms)
        return payload
    except PyJWTError as e:
        raise e

# Example usage:
# secret = "your-strong-secret-key-here"
# try:
#     payload = verify_jwt(token, secret, ['HS256'])
#     print("Valid payload:", payload)
# except PyJWTError as e:
#     print("Invalid token:", e)
