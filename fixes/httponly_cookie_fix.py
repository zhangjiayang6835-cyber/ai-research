"""
Fix: Insecure Cookie — Missing HttpOnly Flag
=============================================
Issue #77 — Cookies containing session tokens or sensitive data must
have the HttpOnly, Secure, and SameSite flags set to prevent XSS-based
session theft, man-in-the-middle interception, and CSRF.

This fix provides:
1. A secure cookie wrapper that enforces HttpOnly, Secure, SameSite
2. Session cookie configuration
3. A Flask helper to replace insecure cookie operations
"""

from __future__ import annotations

import os
from typing import Optional


# ═══════════════════════════════════════════════════════════════════
# 1. Secure cookie configuration
# ═══════════════════════════════════════════════════════════════════

SECURE_COOKIE_DEFAULTS = {
    "httponly": True,      # Prevents JavaScript document.cookie access
    "secure": True,        # Only sent over HTTPS (set False for local dev)
    "samesite": "Lax",     # CSRF mitigation: Lax or Strict
    "max_age": 86400 * 7,  # 7 days — keep sessions reasonable
}


def get_secure_cookie_defaults() -> dict:
    """Return secure cookie defaults.

    Auto-disables ``secure`` for local development (localhost).
    """
    defaults = dict(SECURE_COOKIE_DEFAULTS)
    # Allow non-HTTPS for local development
    hostname = os.environ.get("SERVER_NAME", "")
    if hostname in ("localhost", "127.0.0.1", "0.0.0.0") or "local" in hostname:
        defaults["secure"] = False
    return defaults


# ═══════════════════════════════════════════════════════════════════
# 2. Secure session cookie setter — framework-agnostic
# ═══════════════════════════════════════════════════════════════════


class SecureCookieJar:
    """Replace raw ``response.set_cookie()`` calls with this.

    Enforces HttpOnly=True, Secure=True, SameSite=Lax on ALL cookies
    that carry sensitive data.

    Usage (Flask):
        jar = SecureCookieJar()
        response = jar.set_session_cookie(response, "session_id", token)

    Usage (plain Python):
        jar = SecureCookieJar()
        cookies = jar.build_cookie_string("session_id", token)
    """

    def __init__(self, defaults: Optional[dict] = None):
        self.defaults = defaults or get_secure_cookie_defaults()

    # ── Flask integration ──────────────────────────────────────────

    def set_session_cookie(self, response, name: str, value: str, **overrides):
        """Set a session cookie with enforced security flags.

        Args:
            response: Flask response object.
            name: Cookie name (prefixed with ``__Secure-`` if secure=True).
            value: Cookie value.
            **overrides: Override any default (httponly, secure, samesite, …).
        """
        params = {**self.defaults, **overrides}
        # Prefix for security — indicates the cookie must have Secure flag
        cookie_name = f"__Secure-{name}" if params["secure"] else name
        response.set_cookie(
            cookie_name,
            value=value,
            httponly=params["httponly"],
            secure=params["secure"],
            samesite=params["samesite"],
            max_age=params.get("max_age"),
            path=params.get("path", "/"),
            domain=params.get("domain"),
        )
        return response

    # ── Generic cookie-string builder ──────────────────────────────

    def build_cookie_string(self, name: str, value: str, **overrides) -> str:
        """Build a ``Set-Cookie`` header string with security flags.

        Usage:
            'Set-Cookie: __Secure-session=abc123; HttpOnly; Secure; SameSite=Lax; Path=/'
        """
        params = {**self.defaults, **overrides}
        cookie_name = f"__Secure-{name}" if params["secure"] else name
        parts = [f"{cookie_name}={value}"]
        if params["httponly"]:
            parts.append("HttpOnly")
        if params["secure"]:
            parts.append("Secure")
        if params.get("samesite"):
            parts.append(f"SameSite={params['samesite']}")
        if params.get("max_age") is not None:
            parts.append(f"Max-Age={params['max_age']}")
        parts.append("Path=/")
        if params.get("domain"):
            parts.append(f"Domain={params['domain']}")
        return "; ".join(parts)


# ═══════════════════════════════════════════════════════════════════
# 3. Example: patching a vulnerable Flask login
# ═══════════════════════════════════════════════════════════════════

# B E F O R E  (vulnerable):
#
#   @app.route("/login", methods=["POST"])
#   def login():
#       resp = make_response(redirect("/dashboard"))
#       resp.set_cookie("session", token)  # ❌ No HttpOnly, Secure, SameSite
#       return resp

# A F T E R  (fixed):
#
#   from fixes.httponly_cookie_fix import SecureCookieJar
#   jar = SecureCookieJar()
#
#   @app.route("/login", methods=["POST"])
#   def login():
#       resp = make_response(redirect("/dashboard"))
#       jar.set_session_cookie(resp, "session", token)
#       return resp


# ═══════════════════════════════════════════════════════════════════
# 4. Self-test
# ═══════════════════════════════════════════════════════════════════


def _test():
    jar = SecureCookieJar(defaults={
        "httponly": True,
        "secure": True,
        "samesite": "Lax",
        "max_age": 3600,
    })

    # Test cookie-string builder
    cookie = jar.build_cookie_string("session", "abc123")
    assert "HttpOnly" in cookie, f"Missing HttpOnly: {cookie}"
    assert "Secure" in cookie, f"Missing Secure: {cookie}"
    assert "SameSite=Lax" in cookie, f"Missing SameSite: {cookie}"
    assert "Max-Age=3600" in cookie, f"Missing Max-Age: {cookie}"
    assert "__Secure-session" in cookie, f"Missing prefix: {cookie}"
    assert "Path=/" in cookie, f"Missing Path: {cookie}"

    # Test without secure (dev mode)
    jar2 = SecureCookieJar(defaults={
        "httponly": True,
        "secure": False,
        "samesite": "Strict",
    })
    cookie2 = jar2.build_cookie_string("session", "xyz")
    assert "HttpOnly" in cookie2
    assert "Secure" not in cookie2
    assert "SameSite=Strict" in cookie2

    print("HttpOnly cookie fix: all tests passed")


if __name__ == "__main__":
    _test()
