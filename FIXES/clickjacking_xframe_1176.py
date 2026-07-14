#!/usr/bin/env python3
"""
Fix: Clickjacking via X-Frame-Options Missing → Crypto Withdraw (#1176)
========================================================================
Difficulty: Easy | Bounty: $120

Vulnerability:
  The asset withdrawal page lacks X-Frame-Options and CSP frame-ancestors headers.
  An attacker can construct a transparent iframe to trick users into clicking
  the confirm-withdrawal button.

Fix:
  1. Set X-Frame-Options: DENY on all responses (strictest policy)
  2. Set Content-Security-Policy: frame-ancestors 'none' (modern equivalent)
  3. Add secondary confirmation (CAPTCHA / re-auth) for critical withdrawal operations

Implementation:
  - Flask middleware / WSGI middleware to inject headers globally
  - Decorator for withdrawal endpoints requiring re-authentication
  - CSP header set in web server config (nginx/apache) as defense-in-depth
"""

import functools
from typing import Any, Callable

# ---------------------------------------------------------------------------
# 1. Flask Middleware: X-Frame-Options + CSP
# ---------------------------------------------------------------------------

from flask import Flask, request, g

def security_headers_middleware(app: Flask) -> None:
    """Register before_request hooks to inject security headers on every response."""
    @app.before_request
    def inject_security_headers():
        # Block framing entirely
        g.x_frame_options = "DENY"
        g.csp = "default-src 'self'; frame-ancestors 'none';"

    @app.after_request
    def apply_security_headers(response):
        # X-Frame-Options: DENY — prevents embedding in any iframe
        response.headers["X-Frame-Options"] = "DENY"
        # CSP: frame-ancestors 'none' — modern browser support
        response.headers["Content-Security-Policy"] = "frame-ancestors 'none'"
        # Additional hardening
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        return response


# ---------------------------------------------------------------------------
# 2. Withdrawal Endpoint Protection Decorator
# ---------------------------------------------------------------------------

def require_withdrawal_reconfirm(
    session: dict[str, Any],
    check_token_func: Callable[..., bool],
):
    """
    Decorator that enforces secondary confirmation for withdrawal operations.

    Usage:
        @app.route("/api/withdraw", methods=["POST"])
        @require_withdrawal_reconfirm
        def withdraw():
            ...
    """
    def decorator(fn):
        @functools.wraps(fn)
        def wrapper(*args, **kwargs):
            # Verify user session is valid
            if not session.get("user_id"):
                return {"error": "unauthorized"}, 401

            # Check withdrawal confirmation token (issued after re-auth)
            confirm_token = request.args.get("confirm_token", "")
            if not confirm_token or not check_token_func(confirm_token):
                return {"error": "withdrawal confirmation required"}, 403

            return fn(*args, **kwargs)
        return wrapper
    return decorator


# ---------------------------------------------------------------------------
# 3. Nginx Configuration (defense-in-depth)
# ---------------------------------------------------------------------------

NGINX_CONF = """
# Add to nginx server block for defense-in-depth
server {
    # Block all framing
    add_header X-Frame-Options "DENY" always;

    # CSP: frame-ancestors 'none'
    add_header Content-Security-Policy "frame-ancestors 'none'" always;

    # Additional hardening
    add_header X-Content-Type-Options "nosniff" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    add_header Permissions-Policy "geolocation=(), microphone=(), camera=()" always;

    # Withdrawal endpoint: require POST only
    location /api/withdraw {
        limit_except POST { deny all; }
    }
}
"""


# ---------------------------------------------------------------------------
# 4. WSGI Middleware (framework-agnostic alternative)
# ---------------------------------------------------------------------------

class SecurityHeadersMiddleware:
    """WSGI middleware that adds security headers to every response."""

    def __init__(self, app):
        self.app = app

    def __call__(self, environ, start_response):
        def custom_start_response(status, headers, exc_info=None):
            # Remove any existing X-Frame-Options or CSP
            headers = [
                (k, v) for k, v in headers
                if k.lower() not in ("x-frame-options", "content-security-policy")
            ]
            # Inject security headers
            headers.extend([
                ("X-Frame-Options", "DENY"),
                ("Content-Security-Policy", "frame-ancestors 'none'"),
                ("X-Content-Type-Options", "nosniff"),
            ])
            return start_response(status, headers, exc_info)
        return self.app(environ, custom_start_response)


# ---------------------------------------------------------------------------
# 5. Test / Verification
# ---------------------------------------------------------------------------

def test_security_headers(app):
    """Verify that security headers are present on responses."""
    client = app.test_client()
    resp = client.get("/")
    assert resp.headers.get("X-Frame-Options") == "DENY"
    assert "frame-ancestors 'none'" in resp.headers.get("Content-Security-Policy", "")
    print("[PASS] X-Frame-Options: DENY")
    print("[PASS] CSP: frame-ancestors 'none'")


def test_clickjacking_prevention(app):
    """Verify withdrawal endpoint requires confirmation."""
    client = app.test_client()
    # Without confirm_token, should return 403
    resp = client.post("/api/withdraw", json={"amount": 100})
    assert resp.status_code == 403, f"Expected 403, got {resp.status_code}"
    print("[PASS] Withdrawal blocked without confirmation token")


if __name__ == "__main__":
    from flask import Flask
    app = Flask(__name__)

    @app.route("/")
    def index():
        return "Hello"

    security_headers_middleware(app)
    test_security_headers(app)
    print("\n✅ All security header tests passed!")
