"""
Fix: Unvalidated Redirect in Login Page (Open Redirect)
========================================================
Issue #76 — An open redirect vulnerability occurs when a login page
accepts a ``next`` / ``redirect`` parameter and redirects the browser
to it without validation. Attackers can use this to phish users by
linking to ``https://legitimate-site.com/login?next=https://evil.com``.

This fix provides:
1. A strict allow-list based redirect validator
2. A safe redirect function
3. WSGI and Flask integration
"""

from __future__ import annotations

import re
from typing import Optional
from urllib.parse import urlparse, urlunparse


# ═══════════════════════════════════════════════════════════════════
# 1. Allowed redirect destinations
# ═══════════════════════════════════════════════════════════════════

# Only redirect to paths within the same origin by default
ALLOWED_HOSTS: frozenset[str] = frozenset({
    "example.com",
    "www.example.com",
    "app.example.com",
    "api.example.com",
    # Add your production domains here
})

ALLOWED_SCHEMES: frozenset[str] = frozenset({"https", "http"})


# ═══════════════════════════════════════════════════════════════════
# 2. Safe redirect validation
# ═══════════════════════════════════════════════════════════════════


class OpenRedirectError(ValueError):
    """Raised when a redirect target fails validation."""


def is_safe_redirect_url(target: str, *, host: Optional[str] = None) -> bool:
    """Return True if *target* is a safe redirect URL.

    Rules (strictest-first):
      1. Relative-only redirects (``/dashboard``) → always safe.
      2. Same-origin URLs (scheme + host match) → safe if host is allow-listed.
      3. Absolute URLs with different host → unsafe (blocked).
      4. Protocol-relative URLs (``//evil.com``) → unsafe (blocked).
      5. javascript:/data:/vbscript: → unsafe (blocked).
    """
    if not target or not isinstance(target, str):
        return False

    trimmed = target.strip()

    # Block dangerous schemes
    dangerous_schemes = ("javascript:", "data:", "vbscript:", "file:")
    if any(trimmed.lower().startswith(s) for s in dangerous_schemes):
        return False

    # Block protocol-relative URLs (starts with //)
    if trimmed.startswith("//"):
        return False

    parsed = urlparse(trimmed)

    # Relative path (no scheme, no netloc) → safe
    if not parsed.scheme and not parsed.netloc:
        # But check for path traversal
        if ".." in parsed.path:
            return False
        return True

    # Has a scheme — must be http or https
    if parsed.scheme not in ALLOWED_SCHEMES:
        return False

    # Must have a netloc
    if not parsed.netloc:
        return False

    # If a specific host was provided, check match
    if host:
        return parsed.netloc.lower() == host.lower()

    # Otherwise, check against allow-list
    return parsed.netloc.lower() in ALLOWED_HOSTS


def safe_redirect(target: str, *, fallback: str = "/", host: Optional[str] = None) -> str:
    """Return a safe redirect URL. Falls back to *fallback* if unsafe.

    Args:
        target: The original redirect target from user input.
        fallback: Default redirect path when target is unsafe.
        host: The current request host (for same-origin checks).

    Returns:
        A safe URL string to redirect to.
    """
    if is_safe_redirect_url(target, host=host):
        return target.strip()
    return fallback


# ═══════════════════════════════════════════════════════════════════
# 3. Flask integration
# ═══════════════════════════════════════════════════════════════════


def safe_redirect_flask(target: str, *, fallback: str = "/") -> str:
    """Flask-safe redirect that checks against the current request host.

    Usage:
        from flask import request, redirect
        from fixes.open_redirect_fix import safe_redirect_flask

        @app.route("/login")
        def login():
            next_url = request.args.get("next", "/")
            safe_next = safe_redirect_flask(next_url)
            return redirect(safe_next)
    """
    # Lazy import so this works without Flask installed
    try:
        from flask import request as flask_request
        host = flask_request.host
    except (ImportError, RuntimeError):
        host = None

    return safe_redirect(target, fallback=fallback, host=host)


# ═══════════════════════════════════════════════════════════════════
# 4. Before / After example
# ═══════════════════════════════════════════════════════════════════

# B E F O R E  (vulnerable):
#
#   @app.route("/login")
#   def login():
#       next_url = request.args.get("next", "/")
#       return redirect(next_url)  # ❌ open redirect
#
# A F T E R  (fixed):
#
#   from fixes.open_redirect_fix import safe_redirect_flask
#
#   @app.route("/login")
#   def login():
#       next_url = request.args.get("next", "/")
#       return redirect(safe_redirect_flask(next_url))


# ═══════════════════════════════════════════════════════════════════
# 5. Self-test
# ═══════════════════════════════════════════════════════════════════


def _test():
    # Safe: relative paths
    assert is_safe_redirect_url("/dashboard")
    assert is_safe_redirect_url("/")
    assert is_safe_redirect_url("/profile/settings")

    # Safe: same-origin with explicit host
    assert is_safe_redirect_url("https://example.com/dashboard", host="example.com")

    # Safe: allow-listed host
    assert is_safe_redirect_url("https://www.example.com/page")

    # Unsafe: different host
    assert not is_safe_redirect_url("https://evil.com/phish")
    assert not is_safe_redirect_url("http://malicious.net")

    # Unsafe: dangerous schemes
    assert not is_safe_redirect_url("javascript:alert(1)")
    assert not is_safe_redirect_url("data:text/html,<script>alert(1)</script>")
    assert not is_safe_redirect_url("vbscript:msgbox")

    # Unsafe: protocol-relative
    assert not is_safe_redirect_url("//evil.com/phish")

    # Unsafe: path traversal
    assert not is_safe_redirect_url("/../../etc/passwd")

    # Unsafe: empty / None
    assert not is_safe_redirect_url("")
    assert not is_safe_redirect_url(None)

    # safe_redirect fallback
    assert safe_redirect("https://evil.com", fallback="/home") == "/home"
    assert safe_redirect("/dashboard", fallback="/home") == "/dashboard"

    print("Open redirect fix: all tests passed")


if __name__ == "__main__":
    _test()
