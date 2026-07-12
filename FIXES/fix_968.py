"""
Fix for Issue #968 — Web Cache Deception → Session Token Leak
================================================================

Vulnerability
-------------
Static file CDN is configured to cache /assets/*.css. Attacker tricks victim
into visiting /account/settings/nonexistent.css. CDN caches the page containing
sensitive info (because of .css suffix), and attacker reads the cache to steal
session tokens.

Fix Strategy
------------
1. Cache rules must be based on Content-Type, not file extension.
2. Sensitive/authenticated pages must return Cache-Control: no-store.
3. Configure CDN to never cache pages with authentication cookies.
"""

from __future__ import annotations

import os
import re
from typing import Final

# Sensitive URL patterns that should never be cached
SENSITIVE_PATH_PATTERNS: Final[list[re.Pattern]] = [
    re.compile(r"/account", re.IGNORECASE),
    re.compile(r"/admin", re.IGNORECASE),
    re.compile(r"/settings", re.IGNORECASE),
    re.compile(r"/profile", re.IGNORECASE),
    re.compile(r"/dashboard", re.IGNORECASE),
    re.compile(r"/user", re.IGNORECASE),
    re.compile(r"/billing", re.IGNORECASE),
    re.compile(r"/payment", re.IGNORECASE),
    re.compile(r"/checkout", re.IGNORECASE),
    re.compile(r"/login", re.IGNORECASE),
    re.compile(r"/register", re.IGNORECASE),
    re.compile(r"/password", re.IGNORECASE),
    re.compile(r"/api/private", re.IGNORECASE),
    re.compile(r"/api/v1/me", re.IGNORECASE),
]

# File extensions that should force cache based on Content-Type only
STATIC_EXTENSIONS: Final[set[str]] = {
    ".css", ".js", ".png", ".jpg", ".jpeg", ".gif", ".svg",
    ".woff", ".woff2", ".ttf", ".ico", ".webp", ".mp4",
}


def is_sensitive_path(path: str) -> bool:
    """Check if a URL path contains sensitive content that should not be cached."""
    for pattern in SENSITIVE_PATH_PATTERNS:
        if pattern.search(path):
            return True
    return False


def has_static_extension(path: str) -> bool:
    """Check if a URL path has a static file extension."""
    _, ext = os.path.splitext(path)
    return ext.lower() in STATIC_EXTENSIONS


def has_auth_cookie(headers: dict[str, str]) -> bool:
    """Check if the request contains authentication cookies."""
    cookies = headers.get("Cookie", "")
    auth_patterns = ["session", "token", "auth", "jwt", "sid"]
    return any(pattern in cookies.lower() for pattern in auth_patterns)


def determine_cache_policy(
    path: str,
    content_type: str,
    has_auth: bool,
) -> tuple[str, str]:
    """
    Determine the cache policy for a given request/response.

    Parameters
    ----------
    path : str
        Request URL path.
    content_type : str
        Response Content-Type header.
    has_auth : bool
        Whether the request has authentication.

    Returns
    -------
    tuple of (str, str)
        (Cache-Control header value, reason).
    """
    # Authenticated pages: never cache
    if has_auth:
        return "no-store, no-cache, must-revalidate", "Authenticated request"

    # Sensitive paths: never cache
    if is_sensitive_path(path):
        return "no-store, no-cache, must-revalidate", "Sensitive path"

    # Static content: cache based on Content-Type, not extension
    if content_type.startswith(("text/css", "application/javascript", "image/", "font/")):
        return "public, max-age=31536000, immutable", "Static content by Content-Type"

    # Default: do not cache
    return "no-cache, no-store, must-revalidate", "Default policy"


class CacheDeceptionProtectionMiddleware:
    """
    WSGI middleware that prevents web cache deception attacks.
    """

    def __init__(self, app):
        self.app = app

    def __call__(self, environ, start_response):
        def _start_response(status, response_headers, exc_info=None):
            headers = dict(response_headers)
            path = environ.get("PATH_INFO", "")
            content_type = headers.get("Content-Type", "text/html")
            cookie = environ.get("HTTP_COOKIE", "")

            has_auth = has_auth_cookie({"Cookie": cookie})
            cache_header, reason = determine_cache_policy(path, content_type, has_auth)

            # Override any existing Cache-Control
            headers["Cache-Control"] = cache_header

            # Add X-Content-Type-Options
            if "X-Content-Type-Options" not in headers:
                headers["X-Content-Type-Options"] = "nosniff"

            return start_response(status, list(headers.items()), exc_info)

        return self.app(environ, _start_response)
