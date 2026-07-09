"""
CORS Middleware with Origin whitelist validation.

Fixes CORS misconfiguration:
- No wildcard with credentials
- Origin whitelist validation (no reflection)
- Returns Vary: Origin header
"""

import re
from typing import Optional, Set

# Whitelist of allowed origins
ALLOWED_ORIGINS: Set[str] = {
    "http://localhost:3000",
    "http://localhost:8000",
    "http://localhost:8080",
    "https://ai-research-platform.example.com",
    "https://honeycode-honeypot.example.com",
}

# Regex patterns for allowed origin patterns (e.g., subdomains)
ALLOWED_ORIGIN_PATTERNS = [
    re.compile(r"^https://.*\.ai-research\.example\.com$"),
    re.compile(r"^https://.*\.honeycode-honeypot\.example\.com$"),
]


def is_origin_allowed(origin: Optional[str]) -> bool:
    """
    Validate if the given Origin is in the whitelist.

    Args:
        origin: The Origin header value from the request, or None.

    Returns:
        True if the origin is allowed, False otherwise.
    """
    if origin is None:
        return False

    # Check exact matches
    if origin in ALLOWED_ORIGINS:
        return True

    # Check regex patterns
    for pattern in ALLOWED_ORIGIN_PATTERNS:
        if pattern.match(origin):
            return True

    return False


def get_cors_headers(origin: Optional[str]) -> dict:
    """
    Get appropriate CORS response headers based on Origin validation.

    Never reflects arbitrary Origin values.
    Never combines wildcard (*) with Access-Control-Allow-Credentials: true.

    Args:
        origin: The Origin header value from the request, or None.

    Returns:
        Dictionary of CORS headers to include in the response.
    """
    headers = {
        "Vary": "Origin",
    }

    if origin and is_origin_allowed(origin):
        headers["Access-Control-Allow-Origin"] = origin
        headers["Access-Control-Allow-Credentials"] = "true"
        headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE, OPTIONS"
        headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
        headers["Access-Control-Max-Age"] = "86400"
    else:
        # For non-whitelisted origins, do NOT set Allow-Origin or Allow-Credentials
        # This prevents credential theft via CORS reflection
        pass

    return headers