"""Clickjacking protection helpers for issue #61.

The fix adds frame-busting headers to every HTTP response:
- X-Frame-Options: DENY
- Content-Security-Policy: frame-ancestors 'none'

It is intentionally framework-light so the same behavior can be used from
Flask, plain WSGI, or tests without adding dependencies.
"""

from __future__ import annotations

import unittest
from typing import Callable, Iterable, MutableMapping, Tuple


X_FRAME_OPTIONS = "DENY"
CSP_FRAME_ANCESTORS = "frame-ancestors 'none'"


def _merge_csp(existing: str | None) -> str:
    """Return a CSP value that always includes frame-ancestors 'none'."""
    if not existing:
        return CSP_FRAME_ANCESTORS

    directives = [part.strip() for part in existing.split(";") if part.strip()]
    filtered = [
        directive
        for directive in directives
        if not directive.lower().startswith("frame-ancestors")
    ]
    filtered.append(CSP_FRAME_ANCESTORS)
    return "; ".join(filtered)


def apply_clickjacking_headers(
    headers: MutableMapping[str, str],
) -> MutableMapping[str, str]:
    """Apply clickjacking protections to a mutable headers mapping."""
    headers["X-Frame-Options"] = X_FRAME_OPTIONS
    headers["Content-Security-Policy"] = _merge_csp(
        headers.get("Content-Security-Policy")
    )
    return headers


def install_flask_clickjacking_protection(app):
    """Install response headers on all Flask responses.

    Usage:
        app = Flask(__name__)
        install_flask_clickjacking_protection(app)
    """

    @app.after_request
    def add_clickjacking_headers(response):
        response.headers["X-Frame-Options"] = X_FRAME_OPTIONS
        response.headers["Content-Security-Policy"] = _merge_csp(
            response.headers.get("Content-Security-Policy")
        )
        return response

    return app


class ClickjackingProtectionMiddleware:
    """WSGI middleware that adds frame-busting headers to every response."""

    def __init__(self, app: Callable):
        self.app = app

    def __call__(self, environ, start_response):
        def protected_start_response(
            status: str,
            headers: list[Tuple[str, str]],
            exc_info=None,
        ):
            normalized = {}
            output_headers = []
            for name, value in headers:
                lower = name.lower()
                normalized[lower] = value
                if lower not in {"x-frame-options", "content-security-policy"}:
                    output_headers.append((name, value))

            output_headers.append(("X-Frame-Options", X_FRAME_OPTIONS))
            output_headers.append(
                (
                    "Content-Security-Policy",
                    _merge_csp(normalized.get("content-security-policy")),
                )
            )
            return start_response(status, output_headers, exc_info)

        return self.app(environ, protected_start_response)


class ClickjackingHeaderTests(unittest.TestCase):
    def test_apply_headers_sets_required_values(self):
        headers: dict[str, str] = {}

        apply_clickjacking_headers(headers)

        self.assertEqual(headers["X-Frame-Options"], "DENY")
        self.assertEqual(
            headers["Content-Security-Policy"], "frame-ancestors 'none'"
        )

    def test_existing_csp_is_preserved_and_frame_ancestors_replaced(self):
        headers = {
            "Content-Security-Policy": (
                "default-src 'self'; frame-ancestors https://example.com"
            )
        }

        apply_clickjacking_headers(headers)

        self.assertEqual(
            headers["Content-Security-Policy"],
            "default-src 'self'; frame-ancestors 'none'",
        )

    def test_wsgi_middleware_adds_headers_to_all_responses(self):
        def app(_environ, start_response):
            start_response("200 OK", [("Content-Type", "text/plain")])
            return [b"ok"]

        observed = {}

        def start_response(status, headers, exc_info=None):
            observed["status"] = status
            observed["headers"] = dict(headers)

        response: Iterable[bytes] = ClickjackingProtectionMiddleware(app)(
            {}, start_response
        )

        self.assertEqual(list(response), [b"ok"])
        self.assertEqual(observed["status"], "200 OK")
        self.assertEqual(observed["headers"]["X-Frame-Options"], "DENY")
        self.assertEqual(
            observed["headers"]["Content-Security-Policy"],
            "frame-ancestors 'none'",
        )


if __name__ == "__main__":
    unittest.main()
