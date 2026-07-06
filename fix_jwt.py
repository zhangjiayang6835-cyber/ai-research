import jwt
from jwt.algorithms import get_default_algorithms

# Strong secret (must be at least 32 bytes random)
SECRET_KEY = "your-very-strong-secret-key-at-least-32-characters-long"

def verify_jwt(token):
    try:
        # Decode without verification first to check algorithm
        unverified = jwt.decode(token, options={"verify_signature": False})
        # Check for None algorithm
        if "alg" not in unverified or unverified.get("alg") == "None":
            raise jwt.InvalidTokenError("Algorithm None is not allowed")
        # Verify token with strong secret
        payload = jwt.decode(
            token,
            SECRET_KEY,
            algorithms=["HS256"],  # Restrict to strong algorithms
            options={"require": ["exp", "iat"]}
        )
        # Validate kid if present (allow only known kids)
        if "kid" in payload:
            allowed_kids = ["key1", "key2"]  # Whitelist
            if payload["kid"] not in allowed_kids:
                raise jwt.InvalidTokenError("Invalid kid")
        return payload
    except jwt.ExpiredSignatureError:
        raise
    except jwt.InvalidTokenError as e:
        raise jwt.InvalidTokenError(f"Invalid token: {e}")
    except Exception as e:
        raise jwt.InvalidTokenError(f"Token verification failed: {e}")
