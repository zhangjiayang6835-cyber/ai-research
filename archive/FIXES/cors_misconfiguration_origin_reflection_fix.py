"""
Fix for Issue #955 — CORS Misconfiguration + Origin Reflection → Credential Theft $120
========================================================================================

Vulnerability
-------------
The API response header `Access-Control-Allow-Origin` directly reflects the
request's Origin value, and `Access-Control-Allow-Credentials: true` is set.
This allows any website to make authenticated cross-origin requests and read
the API response, leading to credential theft.

Root Cause
----------
The application echoes the Origin header back without validation, and
enables credentials with a dynamic origin.

Fix Strategy
------------
1. Implement an Origin whitelist for CORS.
2. Never use wildcard (*) with credentials.
3. Return `Vary: Origin` header.
4. Validate the Origin against the whitelist.
5. Reject requests with invalid origins.

Acceptance Criteria
-------------------
- [x] Origin whitelist implemented
- [x] No wildcard + credentials combination allowed
- [x] Vary: Origin header returned
- [x] CORS preflight (OPTIONS) handled correctly
- [x] Only whitelisted origins allowed with credentials
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple


# =============================================================================
# Configuration
# =============================================================================

# Whitelist of allowed origins (no trailing slash)
ALLOWED_ORIGINS: Set[str] = frozenset({
    "https://example.com",
    "https://www.example.com",
    "https://api.example.com",
    "https://app.example.com",
    "https://admin.example.com",
})

# HTTP methods allowed for CORS
ALLOWED_METHODS: Set[str] = frozenset({
    "GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS",
})

# Allowed headers for CORS
ALLOWED_HEADERS: Set[str] = frozenset({
    "Content-Type", "Authorization", "X-Requested-With",
    "X-CSRF-Token", "Accept", "Origin",
})

# Exposed headers
EXPOSED_HEADERS: Set[str] = frozenset({
    "Content-Type", "X-Request-Id", "X-RateLimit-Remaining",
})

# Max age for preflight cache (in seconds)
PREFLIGHT_MAX_AGE: int = 86400  # 24 hours


# =============================================================================
# Origin Validation
# =============================================================================

@dataclass
class OriginValidationResult:
    """Result of origin validation."""
    valid: bool
    normalized_origin: Optional[str] = None
    error: Optional[str] = None


def _normalize_origin(origin: str) -> str:
    """Normalize an origin string."""
    return origin.rstrip("/").lower()


def _is_valid_origin_format(origin: str) -> bool:
    """Check if the origin has a valid format.
    
    Valid formats:
    - https://example.com
    - https://example.com:443
    - null (for special cases)
    """
    if origin == "null":
        return True
    
    # Basic URL validation
    pattern = re.compile(
        r"^https?://"  # scheme
        r"([A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?\.)*"  # subdomain
        r"[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?"  # domain
        r"(?::\d{1,5})?"  # optional port
        r"$"
    )
    return bool(pattern.match(origin))


def validate_origin(origin: Optional[str]) -> OriginValidationResult:
    """Validate an Origin header against the whitelist.
    
    Returns:
        OriginValidationResult with valid flag and normalized origin.
    """
    if not origin:
        return OriginValidationResult(valid=False, error="Missing Origin header")
    
    normalized = _normalize_origin(origin)
    
    if not _is_valid_origin_format(normalized):
        return OriginValidationResult(
            valid=False,
            error=f"Invalid origin format: {origin}",
        )
    
    if normalized in ALLOWED_ORIGINS:
        return OriginValidationResult(valid=True, normalized_origin=normalized)
    
    # Check with default port variations
    if normalized.startswith("https://") and not normalized.endswith(":443"):
        https_variant = f"{normalized}:443"
        if https_variant in ALLOWED_ORIGINS:
            return OriginValidationResult(valid=True, normalized_origin=https_variant)
    
    if normalized.startswith("http://") and not normalized.endswith(":80"):
        http_variant = f"{normalized}:80"
        if http_variant in ALLOWED_ORIGINS:
            return OriginValidationResult(valid=True, normalized_origin=http_variant)
    
    return OriginValidationResult(
        valid=False,
        error=f"Origin '{origin}' not in whitelist",
    )


# =============================================================================
# CORS Response Headers Builder
# =============================================================================

@dataclass
class CORSHeaders:
    """CORS response headers to add to the response."""
    headers: Dict[str, str] = field(default_factory=dict)
    vary: bool = True


def build_cors_headers(
    origin: Optional[str],
    request_method: str = "GET",
    request_headers: Optional[List[str]] = None,
) -> CORSHeaders:
    """Build CORS response headers based on the request origin.
    
    This is the main function to use in your middleware/response handler.
    
    Args:
        origin: The Origin header value from the request.
        request_method: The HTTP method of the request.
        request_headers: The Access-Control-Request-Headers from preflight.
    
    Returns:
        CORSHeaders with appropriate headers.
    """
    result = CORSHeaders()
    
    # Validate origin
    validation = validate_origin(origin)
    
    if not validation.valid:
        # For invalid origins, don't include CORS headers
        # (except for non-credentialed simple requests)
        result.headers["Vary"] = "Origin"
        return result
    
    allowed_origin = validation.normalized_origin or ""
    
    # Set Access-Control-Allow-Origin
    result.headers["Access-Control-Allow-Origin"] = allowed_origin
    
    # Handle preflight
    if request_method.upper() == "OPTIONS":
        result.headers["Access-Control-Allow-Methods"] = ", ".join(sorted(ALLOWED_METHODS))
        result.headers["Access-Control-Allow-Headers"] = ", ".join(sorted(ALLOWED_HEADERS))
        result.headers["Access-Control-Max-Age"] = str(PREFLIGHT_MAX_AGE)
    
    # Always set Vary: Origin (critical for caching proxies)
    result.headers["Vary"] = "Origin"
    
    return result


def build_cors_headers_with_credentials(
    origin: Optional[str],
    request_method: str = "GET",
    request_headers: Optional[List[str]] = None,
) -> CORSHeaders:
    """Build CORS headers with credentials support.
    
    Only sets Allow-Credentials for whitelisted origins.
    Never sets Allow-Credentials with wildcard origin.
    """
    result = build_cors_headers(origin, request_method, request_headers)
    
    validation = validate_origin(origin)
    if validation.valid:
        # Only set credentials for validated origins
        # (never with wildcard)
        result.headers["Access-Control-Allow-Credentials"] = "true"
    
    return result


# =============================================================================
# Middleware / Integration
# =============================================================================

class CORSMiddleware:
    """WSGI/ASGI middleware for CORS protection.
    
    Usage:
        app = CORSMiddleware(app)
    """
    
    def __init__(self, app):
        self.app = app
    
    def __call__(self, environ, start_response):
        def cors_start_response(status, headers, exc_info=None):
            # Add CORS headers
            origin = environ.get("HTTP_ORIGIN", "")
            method = environ.get("REQUEST_METHOD", "GET")
            
            cors = build_cors_headers_with_credentials(origin, method)
            
            new_headers = list(headers)
            for key, value in cors.headers.items():
                new_headers.append((key, value))
            
            return start_response(status, new_headers, exc_info)
        
        return self.app(environ, cors_start_response)


# =============================================================================
# Self-Test
# =============================================================================

def run_self_test() -> List[str]:
    """Run self-test to verify the fix works."""
    errors = []
    
    # Test 1: Valid origin
    result = build_cors_headers_with_credentials("https://example.com")
    assert result.headers.get("Access-Control-Allow-Origin") == "https://example.com"
    assert result.headers.get("Access-Control-Allow-Credentials") == "true"
    assert "Vary" in result.headers
    print("✓ Test 1: Valid origin allowed with credentials")
    
    # Test 2: Invalid origin (not in whitelist)
    result = build_cors_headers_with_credentials("https://evil.com")
    assert "Access-Control-Allow-Origin" not in result.headers
    assert "Access-Control-Allow-Credentials" not in result.headers
    print("✓ Test 2: Invalid origin rejected")
    
    # Test 3: No origin header
    result = build_cors_headers_with_credentials(None)
    assert "Access-Control-Allow-Origin" not in result.headers
    print("✓ Test 3: Missing origin handled gracefully")
    
    # Test 4: Preflight
    result = build_cors_headers_with_credentials("https://example.com", "OPTIONS")
    assert "Access-Control-Allow-Methods" in result.headers
    assert "Access-Control-Max-Age" in result.headers
    print("✓ Test 4: Preflight headers set")
    
    # Test 5: Vary header always present
    result = build_cors_headers_with_credentials(None)
    assert result.headers.get("Vary") == "Origin"
    print("✓ Test 5: Vary: Origin always set")
    
    # Test 6: Never wildcard with credentials
    # (This is enforced by design - we never use *)
    result = build_cors_headers_with_credentials("https://example.com")
    assert result.headers.get("Access-Control-Allow-Origin") != "*"
    print("✓ Test 6: No wildcard origin with credentials")
    
    # Test 7: Origin validation - invalid format
    result = validate_origin("not-a-url")
    assert not result.valid
    print("✓ Test 7: Invalid origin format rejected")
    
    # Test 8: Origin without port matches (the whitelist doesn't have :443)
    result = build_cors_headers_with_credentials("https://example.com")
    assert result.headers.get("Access-Control-Allow-Origin") is not None
    print("✓ Test 8: Origin matched successfully")
    
    return errors


if __name__ == "__main__":
    errors = run_self_test()
    if errors:
        print(f"\nFAILED: {len(errors)} test(s) failed:")
        for e in errors:
            print(f"  - {e}")
    else:
        print("\nAll self-tests passed!")
