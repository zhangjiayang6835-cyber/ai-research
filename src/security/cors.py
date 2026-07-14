"""
CORS Security Module — Fix for Issue #955: CORS Misconfiguration + Origin Reflection
=====================================================================================

Vulnerability
-------------
The API response headers reflect the request's Origin value directly:
  Access-Control-Allow-Origin: {Origin}
  Access-Control-Allow-Credentials: true

This allows any website to make authenticated cross-origin requests and read
the API response, leading to credential theft.

Fix
---
1. Implement an Origin whitelist for CORS.
2. Never use wildcard (*) with credentials.
3. Return `Vary: Origin` header for cache correctness.
4. Validate the Origin against the whitelist before reflecting it.
5. Reject requests with invalid origins (no CORS headers returned).
"""

from __future__ import annotations

import re
from typing import Dict, FrozenSet, Optional, Set, Tuple


# =============================================================================
# Configuration — whitelist of allowed origins
# =============================================================================

# Default allowed origins. Can be overridden via environment variable
# CORS_ALLOWED_ORIGINS (comma-separated, no trailing slash).
import os

_DEFAULT_ORIGINS = (
    "https://app.example.com",
    "https://api.example.com",
    "https://admin.example.com",
    "http://localhost:5000",
    "http://localhost:3000",
)

ALLOWED_ORIGINS: FrozenSet[str] = frozenset(
    o.strip().rstrip("/")
    for o in os.environ.get(
        "CORS_ALLOWED_ORIGINS",
        ",".join(_DEFAULT_ORIGINS),
    ).split(",")
    if o.strip()
)

ALLOWED_METHODS: FrozenSet[str] = frozenset({
    "GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS",
})

ALLOWED_HEADERS: FrozenSet[str] = frozenset({
    "Content-Type", "Authorization", "X-Requested-With",
    "X-CSRF-Token", "Accept", "Origin",
})

EXPOSED_HEADERS: FrozenSet[str] = frozenset({
    "Content-Type", "X-Request-Id",
})

PREFLIGHT_MAX_AGE: int = 86400  # 24 hours


# =============================================================================
# Origin Validation
# =============================================================================

# Regex for basic origin format validation
_ORIGIN_RE = re.compile(
    r"^https?://"                                    # scheme
    r"([A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?\.)*"  # subdomain(s)
    r"[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?"       # domain
    r"(?::\d{1,5})?"                                 # optional port
    r"$"
)


def is_valid_origin(origin: Optional[str]) -> bool:
    """Check if the origin has a valid format.

    Returns True for valid origins and 'null' (special case).
    """
    if not origin:
        return False
    if origin == "null":
        return True
    return bool(_ORIGIN_RE.match(origin))


def is_origin_allowed(origin: Optional[str]) -> bool:
    """Check if the origin is in the whitelist.

    Performs case-insensitive comparison and handles default port
    variations (e.g., https://example.com matches https://example.com:443).
    """
    if not origin:
        return False
    normalized = origin.rstrip("/").lower()
    if normalized in ALLOWED_ORIGINS:
        return True
    # Check default port variations
    if normalized.startswith("https://") and not normalized.endswith(":443"):
        if f"{normalized}:443" in ALLOWED_ORIGINS:
            return True
    if normalized.startswith("http://") and not normalized.endswith(":80"):
        if f"{normalized}:80" in ALLOWED_ORIGINS:
            return True
    return False


# =============================================================================
# CORS Response Headers Builder
# =============================================================================

def build_cors_headers(
    origin: Optional[str],
    request_method: str = "GET",
) -> Dict[str, str]:
    """Build CORS response headers based on the request origin.

    Only returns Access-Control-Allow-Origin for whitelisted origins.
    Never returns wildcard with credentials.

    Args:
        origin: The Origin header value from the request.
        request_method: The HTTP method of the request.

    Returns:
        Dict of CORS headers to add to the response.
    """
    headers: Dict[str, str] = {"Vary": "Origin"}

    if not origin or not is_valid_origin(origin):
        return headers

    if not is_origin_allowed(origin):
        return headers

    allowed_origin = origin.rstrip("/").lower()
    headers["Access-Control-Allow-Origin"] = allowed_origin

    if request_method.upper() == "OPTIONS":
        headers["Access-Control-Allow-Methods"] = ", ".join(sorted(ALLOWED_METHODS))
        headers["Access-Control-Allow-Headers"] = ", ".join(sorted(ALLOWED_HEADERS))
        headers["Access-Control-Allow-Credentials"] = "true"
        headers["Access-Control-Max-Age"] = str(PREFLIGHT_MAX_AGE)
    else:
        headers["Access-Control-Allow-Credentials"] = "true"

    return headers


def apply_cors_headers(response, origin: Optional[str], request_method: str = "GET") -> None:
    """Apply CORS headers to a Flask response object.

    This is the main integration point for Flask apps. Call it in an
    @app.after_request hook or per-route.

    Example:
        @app.after_request
        def add_cors(response):
            apply_cors_headers(response, request.headers.get("Origin"), request.method)
            return response
    """
    headers = build_cors_headers(origin, request_method)
    for key, value in headers.items():
        response.headers[key] = value


# =============================================================================
# Flask Integration
# =============================================================================

def init_cors(app) -> None:
    """Initialize CORS protection for a Flask app.

    Registers an after_request handler that adds CORS headers to every
    response based on the request's Origin header.

    Usage:
        from src.security.cors import init_cors
        init_cors(app)
    """
    @app.after_request
    def add_cors_headers(response):
        origin = None
        method = "GET"
        try:
            from flask import request
            origin = request.headers.get("Origin")
            method = request.method
        except RuntimeError:
            pass
        apply_cors_headers(response, origin, method)
        return response


# =============================================================================
# Self-Test
# =============================================================================

def run_self_test() -> int:
    """Run self-tests. Returns number of failures (0 = all pass)."""
    failures = 0

    def check(name: str, condition: bool) -> None:
        nonlocal failures
        if condition:
            print(f"  ✓ {name}")
        else:
            print(f"  ✗ {name}")
            failures += 1

    print("=== CORS Fix — Self-Tests ===")

    # 1. Valid whitelisted origin
    headers = build_cors_headers("https://app.example.com")
    check("whitelisted origin allowed",
          headers.get("Access-Control-Allow-Origin") == "https://app.example.com")
    check("credentials set for whitelisted origin",
          headers.get("Access-Control-Allow-Credentials") == "true")

    # 2. Invalid origin rejected
    headers = build_cors_headers("https://evil.com")
    check("invalid origin rejected",
          "Access-Control-Allow-Origin" not in headers)

    # 3. No origin header
    headers = build_cors_headers(None)
    check("missing origin handled",
          "Access-Control-Allow-Origin" not in headers)

    # 4. Preflight (OPTIONS)
    headers = build_cors_headers("https://app.example.com", "OPTIONS")
    check("preflight methods set",
          "Access-Control-Allow-Methods" in headers)
    check("preflight max-age set",
          "Access-Control-Max-Age" in headers)

    # 5. Vary header always present
    headers = build_cors_headers(None)
    check("Vary: Origin always set",
          headers.get("Vary") == "Origin")

    # 6. No wildcard with credentials
    headers = build_cors_headers("https://app.example.com")
    check("no wildcard origin",
          headers.get("Access-Control-Allow-Origin") != "*")

    # 7. Invalid origin format
    check("invalid format rejected",
          not is_origin_allowed("not-a-url"))

    # 8. null origin
    check("null origin is valid format",
          is_valid_origin("null"))
    check("null origin not in whitelist",
          not is_origin_allowed("null"))

    print(f"\n{'All tests passed!' if failures == 0 else f'{failures} test(s) failed'}")
    return failures


if __name__ == "__main__":
    run_self_test()