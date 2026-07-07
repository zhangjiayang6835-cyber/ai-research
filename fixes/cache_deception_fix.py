"""
Fix: Web Cache Deception + Session Fixation Combined
=====================================================
Issue #339 — Web Cache Deception tricks caching proxies into
caching sensitive pages by appending a static extension like
.css or .js to the URL. Combined with session fixation, an
attacker can:
1. Fix the victim's session to a known session ID
2. Lure them to a cached sensitive page
3. Read the cached response containing the victim's data

This fix provides:
1. Cache-Control headers that prevent sensitive content caching
2. Session regeneration on login to prevent fixation
3. Vary header enforcement
"""

from __future__ import annotations

import os
import re
from typing import Optional


# ═══════════════════════════════════════════════════════════════════
# Configuration
# ═══════════════════════════════════════════════════════════════════

# File extensions that might be used for cache deception attacks
DECEPTION_EXTENSIONS = re.compile(
    r"\.(css|js|png|jpg|jpeg|gif|ico|svg|woff|woff2|ttf|eot|pdf)$",
    re.IGNORECASE,
)

# Sensitive URL paths that must never be cached
SENSITIVE_PATHS = [
    "/account",
    "/profile",
    "/settings",
    "/admin",
    "/dashboard",
    "/api/user",
    "/api/account",
    "/checkout",
    "/payment",
    "/order",
]


# ═══════════════════════════════════════════════════════════════════
# Custom Error
# ═══════════════════════════════════════════════════════════════════


class CacheDeceptionError(ValueError):
    """Raised when cache deception is detected."""


# ═══════════════════════════════════════════════════════════════════
# PART 1: CACHE-CONTROL HEADER ENFORCEMENT
# ═══════════════════════════════════════════════════════════════════


class CacheControlEnforcer:
    """Enforces strict cache-control headers to prevent cache deception.

    Sets Cache-Control headers based on URL path sensitivity
    to ensure sensitive content is never cached by shared caches.
    """

    SENSITIVE_CACHE = "no-store, no-cache, must-revalidate, private, max-age=0"
    STATIC_CACHE = "public, max-age=31536000, immutable"
    DEFAULT_CACHE = "no-cache, private, max-age=0"

    @staticmethod
    def is_sensitive_path(path: str) -> bool:
        """Check if a URL path contains sensitive content.

        Args:
            path: The URL path to check.

        Returns:
            True if the path is sensitive and must not be cached.
        """
        for sensitive in SENSITIVE_PATHS:
            if path.startswith(sensitive):
                return True
        return False

    @staticmethod
    def is_deception_request(path: str) -> bool:
        """Detect cache deception attack via extension injection.

        Args:
            path: The URL path to check.

        Returns:
            True if the path looks like a cache deception attempt.

        Example:
            >>> check_deception("/account/profile.css")
            True  # Real path with fake extension appended
        """
        # Check if a sensitive path has a static extension appended
        for sensitive in SENSITIVE_PATHS:
            if sensitive in path:
                # Extract the part after the sensitive path
                remainder = path.split(sensitive, 1)[1]
                if DECEPTION_EXTENSIONS.search(remainder):
                    return True
        return False

    @staticmethod
    def get_cache_control_header(path: str) -> str:
        """Get the appropriate Cache-Control header for a URL.

        Args:
            path: The URL path.

        Returns:
            Cache-Control header value.
        """
        if CacheControlEnforcer.is_deception_request(path):
            return CacheControlEnforcer.SENSITIVE_CACHE

        if CacheControlEnforcer.is_sensitive_path(path):
            return CacheControlEnforcer.SENSITIVE_CACHE

        # Check if it's a static file
        if DECEPTION_EXTENSIONS.search(path):
            return CacheControlEnforcer.STATIC_CACHE

        return CacheControlEnforcer.DEFAULT_CACHE

    @staticmethod
    def get_response_headers(path: str) -> dict[str, str]:
        """Get complete set of cache-prevention headers.

        Args:
            path: The URL path.

        Returns:
            Dict of header name to value.
        """
        headers = {
            "Cache-Control": CacheControlEnforcer.get_cache_control_header(path),
        }

        # Always add Vary header to prevent cache poisoning
        headers["Vary"] = "Cookie, Authorization, Accept-Encoding"

        # Add Pragma for HTTP/1.0 compatibility
        if CacheControlEnforcer.is_sensitive_path(path):
            headers["Pragma"] = "no-cache"
            headers["Expires"] = "0"

        return headers


# ═══════════════════════════════════════════════════════════════════
# PART 2: SESSION FIXATION PREVENTION
# ═══════════════════════════════════════════════════════════════════


class SessionFixationPreventer:
    """Prevents session fixation attacks.

    Session fixation occurs when an attacker sets a user's
    session identifier before login. After login, the session
    MUST be regenerated so the attacker's known session ID
    becomes invalid.
    """

    def __init__(self):
        self._session_regenerated = False

    def regenerate_session(self, current_session_id: str) -> str:
        """Regenerate the session ID after authentication.

        This is the PRIMARY defense against session fixation.
        Always call this after successful login/authentication.

        Args:
            current_session_id: The current session ID.

        Returns:
            A new, cryptographically random session ID.
        """
        new_session_id = os.urandom(32).hex()
        self._session_regenerated = True
        return new_session_id

    @staticmethod
    def validate_session_id(session_id: str) -> bool:
        """Validate a session ID for common fixation patterns.

        Checks if the session ID looks like it might be
        attacker-controlled (too short, predictable pattern).

        Args:
            session_id: The session ID to validate.

        Returns:
            True if session ID looks legitimate.
        """
        if not session_id or len(session_id) < 16:
            return False

        # Check for common fixation patterns
        if session_id in ("test", "admin", "1234", "fixated"):
            return False

        # Ensure it looks like a proper random hex string
        if not re.match(r"^[a-f0-9]{32,}$", session_id):
            return False

        return True

    def is_fixated(self, session_id: str) -> bool:
        """Check if a session might be fixated.

        Args:
            session_id: The session ID to check.

        Returns:
            True if session is likely fixated.
        """
        return not self.validate_session_id(session_id)


# ═══════════════════════════════════════════════════════════════════
# PART 3: COMBINED MIDDLEWARE
# ═══════════════════════════════════════════════════════════════════


class CacheDeceptionSessionFixationMiddleware:
    """Combined middleware preventing cache deception and session fixation.

    Integrates both protections into a single middleware layer
    that can be dropped into any web framework.
    """

    def __init__(self):
        self.cache = CacheControlEnforcer()
        self.session = SessionFixationPreventer()

    def process_request(
        self,
        path: str,
        session_id: Optional[str] = None,
    ) -> dict:
        """Process a request through both protection layers.

        Args:
            path: Request URL path.
            session_id: Current session ID (if available).

        Returns:
            Dict with cache headers and session guidance.
        """
        result = {
            "cache_headers": self.cache.get_response_headers(path),
        }

        if session_id:
            result["session_valid"] = self.session.validate_session_id(session_id)
            result["session_fixated"] = self.session.is_fixated(session_id)

        return result


# ═══════════════════════════════════════════════════════════════════
# Self-test
# ═══════════════════════════════════════════════════════════════════


def _test() -> None:
    print("  Testing Cache Deception + Session Fixation fix...")

    # ── Cache deception detection ──
    assert CacheControlEnforcer.is_deception_request("/account/profile.css")
    print("  ✓ Cache deception via /account/profile.css detected")

    assert CacheControlEnforcer.is_deception_request("/settings/avatar.jpg")
    print("  ✓ Cache deception via /settings/avatar.jpg detected")

    assert not CacheControlEnforcer.is_deception_request("/images/logo.png")
    print("  ✓ Legitimate static file not flagged")

    # ── Cache control headers ──
    headers = CacheControlEnforcer.get_response_headers("/account/profile")
    assert "no-store" in headers["Cache-Control"]
    print("  ✓ Sensitive path gets no-store cache header")

    headers = CacheControlEnforcer.get_response_headers("/images/logo.png")
    assert "public" in headers["Cache-Control"]
    print("  ✓ Static file gets public cache header")

    headers = CacheControlEnforcer.get_response_headers("/api/data")
    assert "no-cache" in headers["Cache-Control"]
    print("  ✓ Default path gets no-cache header")

    # ── Vary header always present ──
    headers = CacheControlEnforcer.get_response_headers("/any/path")
    assert "Vary" in headers
    print("  ✓ Vary header always present")

    # ── Session fixation prevention ──
    preventer = SessionFixationPreventer()
    new_sid = preventer.regenerate_session("attacker_known_session")
    assert len(new_sid) == 64  # 32 bytes = 64 hex chars
    print("  ✓ Session regenerated with random ID")

    assert preventer.validate_session_id(new_sid)
    print("  ✓ New session ID is valid")

    assert not preventer.validate_session_id("test")
    print("  ✓ Weak session ID 'test' rejected")

    assert not preventer.validate_session_id("1234")
    print("  ✓ Numeric session ID rejected")

    assert not preventer.validate_session_id("abc")
    print("  ✓ Short session ID rejected")

    # ── Combined middleware ──
    mw = CacheDeceptionSessionFixationMiddleware()
    result = mw.process_request("/account/dashboard.css", "weak_sid")
    assert "no-store" in result["cache_headers"]["Cache-Control"]
    assert result["session_fixated"]
    print("  ✓ Combined middleware detects both attack vectors")

    print("\n  ✓ ALL TESTS PASSED")


if __name__ == "__main__":
    _test()
