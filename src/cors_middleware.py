"""
CORS Middleware with Origin whitelist validation.
Fixes: CORS Misconfiguration + Origin Reflection vulnerability.
"""

from typing import List, Optional
import re


# Whitelist of allowed origins
# These should be configured based on the deployment environment
ALLOWED_ORIGINS: List[str] = [
    "http://localhost:3000",
    "http://localhost:8000",
    "http://localhost:8080",
    "https://ai-research-platform.example.com",
    "https://honeycode-honeypot.example.com",
]

# Regex patterns for allowed origins (for wildcard subdomain support)
ALLOWED_ORIGIN_PATTERNS: List[str] = [
    r"^https://.*\.ai-research\.example\.com$",
    r"^https://.*\.honeycode-honeypot\.example\.com$",
]


def is_origin_allowed(origin: Optional[str]) -> bool:
    """
    Validate if the given Origin is in the whitelist.
    
    Args:
        origin: The Origin header value from the request, or None
        
    Returns:
        True if the origin is allowed, False otherwise
    """
    if origin is None:
        return False
    
    # Check exact matches first
    if origin in ALLOWED_ORIGINS:
        return True
    
    # Check regex patterns
    for pattern in ALLOWED_ORIGIN_PATTERNS:
        if re.match(pattern, origin):
            return True
    
    return False


def get_cors_headers(origin: Optional[str]) -> dict:
    """
    Generate CORS response headers based on the request Origin.
    
    Implements secure CORS:
    - Origin whitelist validation (no reflection of arbitrary origins)
    - No credentials + wildcard combination
    - Returns Vary: Origin header for proper caching
    
    Args:
        origin: The Origin header value from the request, or None
        
    Returns:
        Dictionary of CORS headers to include in the response
    """
    headers = {
        "Vary": "Origin",
    }
    
    if origin is None:
        # No Origin header - do not add CORS headers
        return headers
    
    if is_origin_allowed(origin):
        # Origin is in whitelist - reflect the specific origin
        headers["Access-Control-Allow-Origin"] = origin
        headers["Access-Control-Allow-Credentials"] = "true"
        headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE, OPTIONS"
        headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
        headers["Access-Control-Max-Age"] = "86400"
    else:
        # Origin not allowed - do NOT reflect it
        # Do not add Access-Control-Allow-Origin at all
        # This prevents unauthorized cross-origin access
        pass
    
    return headers