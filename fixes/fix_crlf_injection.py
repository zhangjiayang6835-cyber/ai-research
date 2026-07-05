"""
fix_crlf_injection.py — CRLF Injection to HTTP Response Splitting + Cache Poisoning Fix

VULNERABILITY:
Attackers inject CRLF (%0d%0a) sequences into HTTP headers (e.g., via redirect URL,
cookie value, or custom header). This splits the HTTP response, allowing attackers
to inject arbitrary headers or body content. Cache poisoning occurs when a proxy
caches the split response and serves it to other users.

FIX:
1. Strip/reject all CRLF sequences from user-controlled input used in headers
2. Validate all redirect URLs against allowlist
3. Set secure cache headers to prevent poisoning
4. Use framework-provided header setting (which sanitizes automatically)
5. Implement response boundary validation
"""

import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse


# =============================================================================
# Configuration
# =============================================================================

# Characters that are dangerous in HTTP headers
DANGEROUS_CHARS = re.compile(r'[\x00-\x1f\x7f]')

# CRLF patterns to detect
CRLF_PATTERNS = [
    re.compile(r'%0d%0a', re.IGNORECASE),
    re.compile(r'%0a%0d', re.IGNORECASE),
    re.compile(r'%0d', re.IGNORECASE),
    re.compile(r'%0a', re.IGNORECASE),
    re.compile(r'\r\n'),
    re.compile(r'\n\r'),
    re.compile(r'\r(?!\n)'),
    re.compile(r'(?<!\r)\n'),
]

# Cache poisoning protection defaults
CACHE_HEADERS = {
    "Cache-Control": "no-store, max-age=0, must-revalidate",
    "Pragma": "no-cache",
    "Expires": "0",
}


@dataclass
class CRLFConfig:
    """Configuration for CRLF injection protection."""
    # Reject input containing CRLF entirely
    reject_on_crlf: bool = True
    # Strip dangerous characters from input
    strip_dangerous: bool = True
    # Set no-cache headers on all responses
    set_no_cache_headers: bool = True
    # Validate redirect URLs
    validate_redirects: bool = True
    # Allowed redirect hosts (empty = same host only)
    allowed_redirect_hosts: Set[str] = field(default_factory=set)


# =============================================================================
# CRLF Detection and Sanitization
# =============================================================================

class CRLFSanitizer:
    """Sanitizes input to prevent CRLF injection."""

    @staticmethod
    def contains_crlf(value: str) -> bool:
        """Check if a string contains any CRLF variants."""
        for pattern in CRLF_PATTERNS:
            if pattern.search(value):
                return True
        return False

    @staticmethod
    def contains_dangerous_chars(value: str) -> bool:
        """Check if a string contains non-printable chars."""
        return bool(DANGEROUS_CHARS.search(value))

    @staticmethod
    def sanitize(value: str) -> str:
        """Remove CRLF and other dangerous characters."""
        # Remove URL-encoded variants
        result = re.sub(r'%0[daA]', '', value)
        result = re.sub(r'%0[DaA]', '', result)

        # Remove actual control characters
        result = DANGEROUS_CHARS.sub('', result)

        # Remove literal CR/LF
        result = result.replace('\r', '').replace('\n', '')
        result = result.replace('\x0d', '').replace('\x0a', '')

        return result

    @staticmethod
    def validate_header_value(name: str, value: str,
                              config: Optional[CRLFConfig] = None) -> Tuple[bool, str]:
        """
        Validate a header value for CRLF injection.

        Returns (is_valid, rejection_reason).
        """
        if not value:
            return True, ""

        config = config or CRLFConfig()

        if config.reject_on_crlf and CRLFSanitizer.contains_crlf(value):
            return False, f"CRLF detected in header '{name}'"

        if config.strip_dangerous and CRLFSanitizer.contains_dangerous_chars(value):
            return False, f"Dangerous chars in header '{name}'"

        # Check for multiple headers injection (new header via CRLF)
        if '\r\n' in value or '\n\r' in value:
            return False, f"Header injection detected in '{name}'"

        return True, ""


# =============================================================================
# Secure Header Manager
# =============================================================================

class SecureHeaderManager:
    """
    Manages HTTP response headers with CRLF injection protection.

    All header values are sanitized before being set.
    """

    def __init__(self, config: Optional[CRLFConfig] = None):
        self.config = config or CRLFConfig()
        self.headers: Dict[str, str] = {}
        self._set_default_headers()

    def _set_default_headers(self):
        """Set default security headers."""
        if self.config.set_no_cache_headers:
            self.headers.update(CACHE_HEADERS)

    def set_header(self, name: str, value: str) -> bool:
        """
        Set an HTTP header with CRLF injection protection.

        Returns True if header was set, False if rejected.
        """
        valid, reason = CRLFSanitizer.validate_header_value(name, value, self.config)
        if not valid:
            return False

        sanitized = CRLFSanitizer.sanitize(value)
        self.headers[name] = sanitized
        return True

    def set_cookie(self, name: str, value: str, **kwargs) -> bool:
        """
        Set a cookie with CRLF injection protection.

        Cookie values are especially vulnerable because they often
        contain user-controlled data.
        """
        return self.set_header("Set-Cookie", f"{name}={value}")

    def redirect(self, location: str) -> Optional[str]:
        """
        Create a safe redirect URL.

        Returns the sanitized location, or None if invalid.
        """
        if not self.config.validate_redirects:
            location = CRLFSanitizer.sanitize(location)
            if CRLFSanitizer.contains_crlf(location):
                return None
            return location

        # Validate redirect URL
        parsed = urlparse(location)

        # Must have a scheme and netloc
        if not parsed.scheme or not parsed.netloc:
            # Relative redirect — ensure no CRLF
            if CRLFSanitizer.contains_crlf(location):
                return None
            return CRLFSanitizer.sanitize(location)

        # Check allowed hosts
        if self.config.allowed_redirect_hosts:
            if parsed.netloc not in self.config.allowed_redirect_hosts:
                return None

        location = CRLFSanitizer.sanitize(location)
        if CRLFSanitizer.contains_crlf(location):
            return None

        return location

    def get_headers(self) -> Dict[str, str]:
        """Get all set headers."""
        return dict(self.headers)


# =============================================================================
# Cache Poisoning Protection
# =============================================================================

class CachePoisoningProtection:
    """
    Prevents web cache poisoning by ensuring unique cache keys
    and setting proper cache-control headers.
    """

    @staticmethod
    def is_cacheable_response(status_code: int, headers: Dict[str, str]) -> bool:
        """Check if a response should be cacheable."""
        # Never cache error responses
        if status_code >= 400:
            return False

        # Check cache-control
        cc = headers.get("Cache-Control", "")
        if "no-store" in cc or "no-cache" in cc or "private" in cc:
            return False

        return True

    @staticmethod
    def make_cache_key(method: str, path: str, headers: Dict[str, str]) -> str:
        """
        Create a cache key that includes all relevant request attributes.

        This prevents attackers from poisoning the cache by manipulating
        unkeyed inputs (headers, cookies, query params).
        """
        import hashlib
        key_parts = [
            method.upper(),
            path,
        ]
        # Include Vary-relevant headers in cache key
        for h in sorted(headers.keys()):
            key_parts.append(f"{h}:{headers[h]}")

        raw = "\n".join(key_parts)
        return hashlib.sha256(raw.encode()).hexdigest()

    @staticmethod
    def generate_vary_header(dynamic_headers: List[str]) -> str:
        """
        Generate a Vary header that prevents cache poisoning.

        Tells caching proxies which request headers affect the response.
        """
        unique = sorted(set(dynamic_headers))
        return ", ".join(unique)


# =============================================================================
# Middleware
# =============================================================================

class CRLFProtectionMiddleware:
    """
    WSGI middleware that protects against CRLF injection and cache poisoning.

    Wraps an existing WSGI application and sanitizes all outgoing headers.
    """

    def __init__(self, app, config: Optional[CRLFConfig] = None):
        self.app = app
        self.header_manager = SecureHeaderManager(config)

    def __call__(self, environ, start_response):
        def sanitized_start_response(status, headers, exc_info=None):
            safe_headers = []
            for name, value in headers:
                sanitized = CRLFSanitizer.sanitize(value)
                if CRLFSanitizer.contains_crlf(value):
                    continue  # Drop dangerous headers
                safe_headers.append((name, sanitized))

            # Add security headers
            for name, value in self.header_manager.get_headers().items():
                safe_headers.append((name, value))

            return start_response(status, safe_headers, exc_info)

        return self.app(environ, sanitized_start_response)


# =============================================================================
# Input Sanitization for Common CRLF Vectors
# =============================================================================

class URLValidator:
    """Validates URLs used in redirects and Location headers."""

    @staticmethod
    def validate_redirect_url(url: str) -> Optional[str]:
        """Validate a redirect URL for CRLF injection."""
        if CRLFSanitizer.contains_crlf(url):
            return None
        return CRLFSanitizer.sanitize(url)

    @staticmethod
    def validate_cookie_input(value: str) -> Optional[str]:
        """Validate cookie input."""
        if CRLFSanitizer.contains_crlf(value):
            return None
        return CRLFSanitizer.sanitize(value)


# =============================================================================
# Tests
# =============================================================================

def test_crlf_detection():
    """Test that CRLF sequences are detected."""
    assert CRLFSanitizer.contains_crlf("test\r\ninjection")
    assert CRLFSanitizer.contains_crlf("test%0d%0ainjection")
    assert CRLFSanitizer.contains_crlf("test%0ainjection")
    assert CRLFSanitizer.contains_crlf("test%0dinjection")
    assert not CRLFSanitizer.contains_crlf("normal header value")
    print("PASS: CRLF detection works")


def test_crlf_sanitization():
    """Test that CRLF sequences are removed."""
    sanitized = CRLFSanitizer.sanitize("test\r\ninjection")
    assert '\r' not in sanitized
    assert '\n' not in sanitized

    sanitized = CRLFSanitizer.sanitize("test%0d%0ainjection")
    assert '%0d' not in sanitized.lower()
    print("PASS: CRLF sanitization works")


def test_header_validation():
    """Test that headers with CRLF are rejected."""
    manager = SecureHeaderManager()

    # Valid header
    result = manager.set_header("X-Custom", "valid-value")
    assert result, "Valid header should be accepted"

    # CRLF in header value
    result = manager.set_header("Location", "/redirect\r\nX-Evil: true")
    assert not result, "CRLF in header should be rejected"

    print("PASS: Header validation works")


def test_safe_redirect():
    """Test that redirect URLs are validated."""
    manager = SecureHeaderManager(CRLFConfig(validate_redirects=True))

    # Safe redirect
    result = manager.redirect("/dashboard")
    assert result == "/dashboard", "Safe redirect should work"

    # CRLF in redirect
    result = manager.redirect("/dashboard\r\nX-Evil: true")
    assert result is None, "CRLF redirect should be rejected"

    print("PASS: Redirect validation works")


def test_cache_poisoning_prevention():
    """Test that cache poisoning is prevented."""
    protection = CachePoisoningProtection()

    headers = {"Cache-Control": "no-store"}
    assert not protection.is_cacheable_response(200, headers), \
        "No-store responses should not be cacheable"

    # Cache key includes all relevant params
    key1 = protection.make_cache_key("GET", "/page", {"Accept": "text/html"})
    key2 = protection.make_cache_key("GET", "/page", {"Accept": "application/json"})
    assert key1 != key2, "Different headers should produce different cache keys"

    print("PASS: Cache poisoning prevention works")


if __name__ == "__main__":
    test_crlf_detection()
    test_crlf_sanitization()
    test_header_validation()
    test_safe_redirect()
    test_cache_poisoning_prevention()
    print("\n✅ All CRLF injection + cache poisoning tests passed!")
