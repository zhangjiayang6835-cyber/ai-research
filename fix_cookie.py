# Fix: Set HttpOnly flag when setting cookies
# Example using Flask
from flask import make_response

def set_secure_cookie(response, name, value, **kwargs):
    """
    Set a cookie with HttpOnly flag enabled.
    """
    response.set_cookie(
        name,
        value,
        httponly=True,  # Prevents JavaScript access (XSS mitigation)
        secure=True,    # Optional: ensure cookie sent over HTTPS only
        samesite='Lax', # Optional: CSRF protection
        **kwargs
    )
    return response

# Usage:
# response = make_response("Hello")
# response = set_secure_cookie(response, 'session_id', 'abc123')
