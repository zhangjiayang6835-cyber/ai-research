"""
Fix for Issue #961 — Web Cache Poisoning via Unkeyed Header
==============================================================

Vulnerability
-------------
CDN/reverse proxy treats X-Forwarded-Host as affecting the response but does
not include it in the cache key. Attackers set a malicious X-Forwarded-Host
to make the CDN cache a page containing malicious JS, distributed to all users.

Fix Strategy
------------
1. Include all response-affecting headers in the cache key.
2. Normalize the Vary response header to only include essential headers.
3. Reject non-standard headers from origin.
"""

from __future__ import annotations

import hashlib
import re
from typing import Any, Final

# Headers that MUST be part of the cache key
REQUIRED_CACHE_KEY_HEADERS: Final[set[str]] = {
    "host", "accept-encoding", "accept-language",
    "x-forwarded-host", "x-forwarded-proto", "x-forwarded-for",
}

# Headers that are NEVER safe to vary on from user input
DANGEROUS_USER_HEADERS: Final[set[str]] = {
    "x-forwarded-host", "x-forwarded-for", "x-forwarded-proto",
    "x-original-url", "x-rewrite-url", "x-original-host",
}

# Non-standard headers that should be stripped before caching
NON_STANDARD_HEADERS: Final[re.Pattern] = re.compile(r"^x-", re.IGNORECASE)


def generate_cache_key(
    method: str,
    path: str,
    headers: dict[str, str],
    include_headers: set[str] | None = None,
) -> str:
    """
    Generate a deterministic cache key that includes all relevant headers.

    Parameters
    ----------
    method : str
        HTTP method.
    path : str
        Request path.
    headers : dict
        Request headers.
    include_headers : set or None
        Additional headers to include in the cache key.

    Returns
    -------
    str
        SHA-256 cache key.
    """
    if include_headers is None:
        include_headers = REQUIRED_CACHE_KEY_HEADERS

    key_parts = [method, path]
    for header in sorted(include_headers):
        value = headers.get(header, "")
        key_parts.append(f"{header.lower()}:{value}")

    return hashlib.sha256("|".join(key_parts).encode()).hexdigest()


def normalize_vary_header(vary: str) -> str:
    """
    Normalize the Vary response header.

    Remove dangerous user-controlled headers from Vary, keep only
    safe headers like Accept-Encoding.
    """
    if not vary:
        return "Accept-Encoding"

    headers = [h.strip().lower() for h in vary.split(",")]
    safe_headers = [h for h in headers if h not in DANGEROUS_USER_HEADERS]
    if not safe_headers:
        safe_headers = ["Accept-Encoding"]
    return ", ".join(safe_headers)


def sanitize_cache_headers(headers: dict[str, str]) -> dict[str, str]:
    """
    Strip non-standard headers from the response before caching.

    This prevents cache poisoning via custom x-* headers.
    """
    safe = {}
    for key, value in headers.items():
        if NON_STANDARD_HEADERS.match(key) and key.lower() not in REQUIRED_CACHE_KEY_HEADERS:
            continue  # Skip non-standard headers
        safe[key] = value
    return safe


class CachePoisoningProtectionMiddleware:
    """Middleware that protects against web cache poisoning."""

    def __init__(self, app):
        self.app = app

    def __call__(self, environ, start_response):
        def _start_response(status, response_headers, exc_info=None):
            headers = dict(response_headers)
            # Normalize Vary header
            if "Vary" in headers:
                headers["Vary"] = normalize_vary_header(headers["Vary"])
            # Add Cache-Control for sensitive pages
            path = environ.get("PATH_INFO", "")
            if any(sensitive in path for sensitive in ("/account", "/admin", "/settings", "/profile")):
                headers["Cache-Control"] = "no-store, no-cache, must-revalidate"
            return start_response(status, list(headers.items()), exc_info)

        return self.app(environ, _start_response)
