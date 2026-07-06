"""
Fix for Issue #15 — Open Redirect in Login Redirect
=====================================================

Vulnerability
-------------
Login redirect trusts any ``next`` URL parameter without validation,
allowing phishing redirects to attacker-controlled domains.

Fix Strategy
------------
1. Maintain an allow-list of trusted hostnames.
2. Parse the redirect URL and verify the hostname is trusted.
3. Fall back to a safe default (e.g., ``/dashboard``) for untrusted URLs.
"""

from __future__ import annotations

from urllib.parse import urlparse

TRUSTED_HOSTS = {"localhost", "127.0.0.1", "example.com"}
DEFAULT_REDIRECT = "/dashboard"


def safe_redirect(url: str) -> str:
    """Return a safe redirect URL, falling back to DEFAULT_REDIRECT."""
    if not url:
        return DEFAULT_REDIRECT

    parsed = urlparse(url)

    # Allow relative URLs (no scheme, no netloc)
    if not parsed.scheme and not parsed.netloc:
        return url

    # Check hostname against trusted list
    hostname = parsed.hostname or ""
    if hostname in TRUSTED_HOSTS:
        return url

    return DEFAULT_REDIRECT
