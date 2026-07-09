"""
fix_cors_origin_reflection.py — CORS Misconfiguration + Origin Reflection Fix

Issue #746 — API response header `Access-Control-Allow-Origin: {Origin}`
directly reflects request Origin with `Access-Control-Allow-Credentials: true`,
allowing any website to read API responses cross-origin.

FIX:
1. Implement Origin whitelist validation
2. Never allow credentials + wildcard Origin combination
3. Return Vary: Origin header
"""

from __future__ import annotations

import json
import re
from typing import Any, Dict, List, Optional, Set, Tuple


# ═══════════════════════════════════════════════════════════════════
# Configuration
# ═══════════════════════════════════════════════════════════════════

# Default allowed origins (whitelist)
DEFAULT_ALLOWED_ORIGINS: Set[str] = {
    "https://example.com",
    "https://app.example.com",
    "https://admin.example.com",
}

# Origins that should NEVER be allowed
BLOCKED_ORIGIN_PATTERNS = [
    r"^https?://.*\.evil\.com$",
    r"^https?://.*\.malicious\.(net|org)$",
    r"^https?://localhost[:\s]",
    r"^https?://127\.0\.0\.1[:\s]",
    r"^https?://0\.0\.0\.0[:\s]",
    r"^data:",
    r"^file:",
    r"^chrome-extension:",
]

# Headers that should NOT be exposed to untrusted origins
SENSITIVE_EXPOSED_HEADERS: Set[str] = {
    "Authorization",
    "Set-Cookie",
    "X-Session-Token",
    "X-API-Key",
    "X-CSRF-Token",
}


# ═══════════════════════════════════════════════════════════════════
# 1. Origin Validator
# ═══════════════════════════════════════════════════════════════════


class OriginValidator:
    """Validate and sanitize Origin headers for CORS."""

    def __init__(self, allowed_origins: Optional[Set[str]] = None):
        self.allowed_origins = allowed_origins or DEFAULT_ALLOWED_ORIGINS
        self._compiled_blocked = [
            re.compile(p) for p in BLOCKED_ORIGIN_PATTERNS
        ]

    def is_valid_origin(self, origin: Optional[str]) -> bool:
        """Check if an Origin is valid (not null, not blocked)."""
        if not origin:
            return False

        # Null origin is not valid for credentialed requests
        if origin == "null":
            return False

        # Check against blocked patterns
        for pattern in self._compiled_blocked:
            if pattern.search(origin):
                return False

        # Basic URL validation
        if not origin.startswith(("http://", "https://")):
            return False

        return True

    def is_allowed_origin(self, origin: Optional[str]) -> bool:
        """Check if an Origin is in the whitelist."""
        if not origin:
            return False

        # Exact match against whitelist
        if origin in self.allowed_origins:
            return True

        # Subdomain wildcard support (if configured)
        for allowed in self.allowed_origins:
            if allowed.startswith("https://*."):
                domain_part = allowed[10:]  # Remove "https://*."
                if origin.endswith(domain_part):
                    return True

        return False

    def validate(self, origin: Optional[str]) -> Tuple[bool, str]:
        """Full validation of an Origin header.

        Args:
            origin: The Origin header value from the request

        Returns:
            Tuple of (is_valid, error_message)
        """
        if not origin:
            return False, "Missing Origin header"

        if not self.is_valid_origin(origin):
            return False, f"Invalid or blocked origin: {origin}"

        if not self.is_allowed_origin(origin):
            return False, f"Origin not in whitelist: {origin}"

        return True, ""


# ═══════════════════════════════════════════════════════════════════
# 2. CORS Response Builder
# ═══════════════════════════════════════════════════════════════════


class CORSResponseBuilder:
    """Build secure CORS response headers.

    Original vulnerable code:
        response.setHeader("Access-Control-Allow-Origin", request.getHeader("Origin"))
        response.setHeader("Access-Control-Allow-Credentials", "true")

    Fixed code:
        builder = CORSResponseBuilder()
        headers = builder.build_cors_headers(request.getHeader("Origin"))
    """

    def __init__(self, allowed_origins: Optional[Set[str]] = None):
        self.validator = OriginValidator(allowed_origins)

    def build_cors_headers(
        self,
        origin: Optional[str],
        allow_credentials: bool = True,
        allow_methods: Optional[List[str]] = None,
        allow_headers: Optional[List[str]] = None,
        expose_headers: Optional[List[str]] = None,
        max_age: int = 86400,
    ) -> Dict[str, str]:
        """Build secure CORS response headers.

        Args:
            origin: Request Origin header
            allow_credentials: Whether to allow credentials
            allow_methods: Allowed HTTP methods
            allow_headers: Allowed request headers
            expose_headers: Headers to expose to the client
            max_age: Preflight cache duration (seconds)

        Returns:
            Dict of response headers
        """
        headers: Dict[str, str] = {}

        # Validate origin
        is_valid, _ = self.validator.validate(origin)

        if is_valid:
            # Use the validated origin (not wildcard)
            headers["Access-Control-Allow-Origin"] = origin

            # Add Vary header for caching proxies
            headers["Vary"] = "Origin"

            # Credentials support
            if allow_credentials:
                headers["Access-Control-Allow-Credentials"] = "true"

            # Methods
            if allow_methods:
                headers["Access-Control-Allow-Methods"] = ", ".join(allow_methods)

            # Headers
            if allow_headers:
                headers["Access-Control-Allow-Headers"] = ", ".join(allow_headers)

            # Exposed headers (filter sensitive ones)
            if expose_headers:
                safe_exposed = [
                    h for h in expose_headers
                    if h not in SENSITIVE_EXPOSED_HEADERS
                ]
                if safe_exposed:
                    headers["Access-Control-Expose-Headers"] = ", ".join(safe_exposed)
        else:
            # Invalid origin — deny with minimal headers
            headers["Access-Control-Allow-Origin"] = "https://example.com"
            headers["Vary"] = "Origin"

        return headers

    def build_preflight_headers(
        self,
        origin: Optional[str],
        request_method: Optional[str] = None,
        request_headers: Optional[List[str]] = None,
    ) -> Dict[str, str]:
        """Build CORS preflight (OPTIONS) response headers."""
        headers = self.build_cors_headers(
            origin=origin,
            allow_methods=request_method
            and [request_method]
            or ["GET", "POST", "PUT", "DELETE", "PATCH"],
            allow_headers=request_headers
            or ["Content-Type", "Authorization", "X-Requested-With"],
        )
        headers["Access-Control-Max-Age"] = "86400"
        return headers


# ═══════════════════════════════════════════════════════════════════
# 3. WSGI Middleware
# ═══════════════════════════════════════════════════════════════════


class CORSProtectionMiddleware:
    """WSGI middleware that adds secure CORS headers to responses."""

    def __init__(self, app, allowed_origins: Optional[Set[str]] = None):
        self.app = app
        self.builder = CORSResponseBuilder(allowed_origins)

    def __call__(self, environ, start_response):
        origin = environ.get("HTTP_ORIGIN")
        method = environ.get("REQUEST_METHOD")

        def secure_start_response(status, headers, exc_info=None):
            # Build CORS headers
            cors_headers = self.builder.build_cors_headers(origin)

            # Add CORS headers to response
            for name, value in cors_headers.items():
                headers.append((name, value))

            return start_response(status, headers, exc_info)

        # Handle preflight
        if method == "OPTIONS":
            preflight_headers = self.builder.build_preflight_headers(
                origin,
                environ.get("HTTP_ACCESS_CONTROL_REQUEST_METHOD"),
            )
            # Convert to list of tuples
            header_list = list(preflight_headers.items())
            start_response("204 No Content", header_list)
            return [b""]

        return self.app(environ, secure_start_response)


# ═══════════════════════════════════════════════════════════════════
# 4. Direct Fix
# ═══════════════════════════════════════════════════════════════════


def fix_cors_origin_reflection(
    origin: str,
    allowed_origins: Optional[Set[str]] = None,
) -> Dict[str, str]:
    """Drop-in replacement for vulnerable CORS header setting.

    Original vulnerable code:
        headers["Access-Control-Allow-Origin"] = request.getHeader("Origin")
        headers["Access-Control-Allow-Credentials"] = "true"

    Fixed code:
        headers = fix_cors_origin_reflection(request.getHeader("Origin"))
    """
    builder = CORSResponseBuilder(allowed_origins)
    return builder.build_cors_headers(origin)


def is_safe_origin(origin: str) -> bool:
    """Quick check if an Origin is safe for CORS."""
    validator = OriginValidator()
    return validator.is_valid_origin(origin) and validator.is_allowed_origin(origin)


# ═══════════════════════════════════════════════════════════════════
# Tests
# ═══════════════════════════════════════════════════════════════════


def test_origin_validation():
    """Test origin validation."""
    validator = OriginValidator()

    # Valid origins
    assert validator.is_valid_origin("https://example.com")
    assert validator.is_valid_origin("https://app.example.com")

    # Invalid origins
    assert not validator.is_valid_origin("")
    assert not validator.is_valid_origin(None)
    assert not validator.is_valid_origin("null")
    assert not validator.is_valid_origin("http://localhost:3000")
    assert not validator.is_valid_origin("data:text/html,<script>alert(1)</script>")
    assert not validator.is_valid_origin("file:///etc/passwd")

    print("PASS: Origin validation")


def test_whitelist():
    """Test origin whitelist."""
    validator = OriginValidator(
        allowed_origins={"https://example.com", "https://app.example.com"}
    )

    assert validator.is_allowed_origin("https://example.com")
    assert validator.is_allowed_origin("https://app.example.com")
    assert not validator.is_allowed_origin("https://evil.com")
    assert not validator.is_allowed_origin("https://example.com.evil.com")

    print("PASS: Origin whitelist")


def test_cors_headers():
    """Test CORS header generation."""
    builder = CORSResponseBuilder(
        allowed_origins={"https://example.com"}
    )

    # Valid origin
    headers = builder.build_cors_headers("https://example.com")
    assert headers.get("Access-Control-Allow-Origin") == "https://example.com"
    assert headers.get("Access-Control-Allow-Credentials") == "true"
    assert headers.get("Vary") == "Origin"

    # Invalid origin
    headers = builder.build_cors_headers("https://evil.com")
    assert headers.get("Access-Control-Allow-Origin") != "https://evil.com"
    assert headers.get("Vary") == "Origin"

    print("PASS: CORS header generation")


def test_credentials_wildcard_prevention():
    """Test that credentials + wildcard is prevented."""
    builder = CORSResponseBuilder(
        allowed_origins={"https://example.com"}
    )

    # Valid origin with credentials
    headers = builder.build_cors_headers(
        "https://example.com", allow_credentials=True
    )
    assert headers.get("Access-Control-Allow-Credentials") == "true"
    assert headers.get("Access-Control-Allow-Origin") != "*"

    print("PASS: Credentials + wildcard prevention")


def test_preflight():
    """Test CORS preflight handling."""
    builder = CORSResponseBuilder(
        allowed_origins={"https://example.com"}
    )

    headers = builder.build_preflight_headers(
        "https://example.com",
        request_method="POST",
        request_headers=["Content-Type", "Authorization"],
    )

    assert headers.get("Access-Control-Allow-Origin") == "https://example.com"
    assert "POST" in headers.get("Access-Control-Allow-Methods", "")
    assert headers.get("Access-Control-Max-Age") == "86400"

    print("PASS: Preflight handling")


def test_fix_cors_origin_reflection():
    """Test drop-in replacement function."""
    # Valid origin
    headers = fix_cors_origin_reflection(
        "https://example.com",
        allowed_origins={"https://example.com"},
    )
    assert headers.get("Access-Control-Allow-Origin") == "https://example.com"
    assert "Vary" in headers

    # Invalid origin (not in whitelist)
    headers = fix_cors_origin_reflection(
        "https://evil.com",
        allowed_origins={"https://example.com"},
    )
    assert headers.get("Access-Control-Allow-Origin") != "https://evil.com"

    print("PASS: fix_cors_origin_reflection")


def test_is_safe_origin():
    """Test is_safe_origin function."""
    # Need to set up with default allowed origins
    # Default has https://example.com
    assert is_safe_origin("https://example.com")  # In default whitelist
    assert not is_safe_origin("https://evil.com")
    assert not is_safe_origin("")

    print("PASS: is_safe_origin")


def test_sensitive_headers_filtering():
    """Test that sensitive headers are not exposed."""
    builder = CORSResponseBuilder(
        allowed_origins={"https://example.com"}
    )

    headers = builder.build_cors_headers(
        "https://example.com",
        expose_headers=["Authorization", "X-Session-Token", "Content-Type"],
    )

    exposed = headers.get("Access-Control-Expose-Headers", "")
    assert "Authorization" not in exposed
    assert "X-Session-Token" not in exposed
    assert "Content-Type" in exposed

    print("PASS: Sensitive header filtering")


if __name__ == "__main__":
    test_origin_validation()
    test_whitelist()
    test_cors_headers()
    test_credentials_wildcard_prevention()
    test_preflight()
    test_fix_cors_origin_reflection()
    test_is_safe_origin()
    test_sensitive_headers_filtering()
    print("\n✅ ALL 8 TESTS PASSED — CORS Origin Reflection Fix Complete!")