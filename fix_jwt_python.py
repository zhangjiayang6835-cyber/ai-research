import jwt

def verify_jwt(token, public_key):
    """
    Securely verify a JWT token using the RS256 algorithm.
    This prevents algorithm confusion and key injection attacks.
    """
    try:
        # Explicitly specify the allowed algorithms; never trust the header's 'alg' field.
        payload = jwt.decode(
            token,
            public_key,
            algorithms=['RS256']  # Only RS256 is allowed
        )
        return payload
    except jwt.ExpiredSignatureError:
        raise ValueError("Token has expired")
    except jwt.InvalidTokenError as e:
        raise ValueError(f"Invalid token: {e}")

# Example usage:
# public_key = open('public.pem').read()
# try:
#     data = verify_jwt(token, public_key)
#     print(data)
# except ValueError as e:
#     print(e)
