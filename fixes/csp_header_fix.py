"""
Fix: Missing Content Security Policy (CSP) Header
==================================================
Issue #75 — A Content Security Policy header prevents XSS, clickjacking,
data injection, and other code-injection attacks by restricting which
resources the browser is allowed to load.

This fix provides a WSGI middleware and Flask extension that adds a
strict CSP header to every HTTP response.

Security benefits:
- Blocks inline scripts (XSS)
- Blocks data: URIs in scripts
- Blocks eval()
- Restricts object, frame, and form actions
- Reports violations via report-uri / report-to
"""

from __future__ import annotations

from typing import Callable


# ═══════════════════════════════════════════════════════════════════
# 1. CSP policy definition
# ═══════════════════════════════════════════════════════════════════

# Strict CSP that blocks XSS, data injection, and UI redress attacks
STRICT_CSP = (
    "default-src 'self'; "
    "script-src 'self'; "
    "style-src 'self' 'unsafe-inline'; "  # unsafe-inline for legitimate UI frameworks
    "img-src 'self' data:; "
    "font-src 'self'; "
    "object-src 'none'; "
    "frame-ancestors 'none'; "
    "form-action 'self'; "
    "base-uri 'self'; "
    "block-all-mixed-content; "
    "upgrade-insecure-requests; "
)

# For reporting — set CSP_REPORT_URI env var in production
CSP_REPORT_URI = None  # e.g. "https://example.com/csp-report"


def _build_csp() -> str:
    """Build the final CSP string, conditionally appending report-uri."""
    csp = STRICT_CSP
    if CSP_REPORT_URI:
        csp += f"report-uri {CSP_REPORT_URI}; "
        csp += f"report-to csp-endpoint; "
    return csp


# ═══════════════════════════════════════════════════════════════════
# 2. WSGI middleware — works with any WSGI framework
# ═══════════════════════════════════════════════════════════════════


class CSPMiddleware:
    """WSGI middleware that adds Content-Security-Policy to every response.

    Usage:
        from wsgiref.simple_server import make_server
        app = CSPMiddleware(my_wsgi_app)
        make_server('', 8000, app).serve_forever()
    """

    def __init__(self, app: Callable):
        self.app = app
        self._csp = _build_csp()

    def __call__(self, environ, start_response):
        def _csp_start_response(status, headers, exc_info=None):
            # Add CSP header; overwrite any existing one
            headers = [
                (name, value)
                for name, value in headers
                if name.lower() != "content-security-policy"
            ]
            headers.append(("Content-Security-Policy", self._csp))
            return start_response(status, headers, exc_info)

        return self.app(environ, _csp_start_response)


# ═══════════════════════════════════════════════════════════════════
# 3. Flask extension
# ═══════════════════════════════════════════════════════════════════


def install_flask_csp(app) -> None:
    """Install CSP headers on all Flask responses via after_request.

    Usage:
        from flask import Flask
        app = Flask(__name__)
        install_flask_csp(app)
    """
    csp = _build_csp()

    @app.after_request
    def add_csp(response):
        response.headers["Content-Security-Policy"] = csp
        return response


# ═══════════════════════════════════════════════════════════════════
# 4. Low-level helper — for manual / middleware-free use
# ═══════════════════════════════════════════════════════════════════


def apply_csp_header(headers: dict) -> dict:
    """Add CSP header to a headers dict (mutates and returns it)."""
    headers["Content-Security-Policy"] = _build_csp()
    return headers


# ═══════════════════════════════════════════════════════════════════
# 5. Self-test
# ═══════════════════════════════════════════════════════════════════


def _test():
    # Test WSGI middleware
    def dummy_app(environ, start_response):
        start_response("200 OK", [("Content-Type", "text/plain")])
        return [b"ok"]

    observed_headers = {}

    def capture_start_response(status, headers, exc_info=None):
        observed_headers["headers"] = dict(headers)

    app = CSPMiddleware(dummy_app)
    list(app({}, capture_start_response))

    csp = observed_headers["headers"].get("Content-Security-Policy", "")
    assert "default-src 'self'" in csp
    assert "script-src 'self'" in csp
    assert "object-src 'none'" in csp
    assert "frame-ancestors 'none'" in csp
    print("CSP fix: all tests passed")


if __name__ == "__main__":
    _test()
