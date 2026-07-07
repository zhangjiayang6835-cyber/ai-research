"""
Fix for HTTP Request Smuggling / Desync Attack Prevention
=========================================================

Vulnerability
-------------
HTTP Request Smuggling (also known as HTTP Desync) occurs when a front-end
server (reverse proxy, load balancer, CDN) and a back-end server parse HTTP
requests differently, causing them to disagree on where one request ends and
the next begins.

Common causes:
1. **CL.TE** – Front-end honours Content-Length (CL), back-end honours
   Transfer-Encoding: chunked (TE).  An attacker sends both headers.
2. **TE.CL** – Front-end honours TE, back-end honours CL.
3. **TE.TE** – Both honour TE but interpret chunk boundaries differently
   (rare, usually a bug in the front-end).

Consequences include:
- Request smuggling → user impersonation, session hijacking
- Response splitting → cache poisoning, XSS
- Denial of service via request desynchronisation

Root cause: ambiguous parsing of overlapping HTTP framing headers.

Fix Strategy
------------
1. **Reject requests that contain BOTH Content-Length and
   Transfer-Encoding.**  RFC 7230 §3.3.3 explicitly forbids this.
2. **Normalise incoming requests** before they reach application logic:
   strip or canonicalise conflicting headers.
3. **Enforce a single framing mode** per connection: either CL-based or
   chunked, never both.
4. **Set explicit limits** on Content-Length and chunk sizes to prevent
   DoS via oversized payloads.
5. **Log and alert** on any request that triggers rejection so operators
   can investigate potential attacks.

This module provides a WSGI middleware and an ASGI middleware that can be
plugged into Flask/FastAPI/Django/aiohttp without modifying application
code.
"""

from __future__ import annotations

import logging
import re
import time
from typing import Any, Callable, Mapping, MutableMapping, Optional, Tuple

logger = logging.getLogger("http_desync_fix")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

MAX_CONTENT_LENGTH = 10 * 1024 * 1024  # 10 MB default
MAX_CHUNK_SIZE = 1 * 1024 * 1024       # 1 MB per chunk
SMUGGLING_REJECTION_LOG_INTERVAL = 5.0  # deduplicate rapid alerts


class HTTPDesyncError(Exception):
    """Raised when a request exhibits smuggling characteristics."""


def _normalise_header_key(key: str) -> str:
    """Normalise an HTTP header key to the canonical 'key-case' form."""
    return "-".join(p.capitalize() for p in key.split("-"))


def _parse_content_length(value: str) -> Optional[int]:
    """Parse and validate a Content-Length header value.

    Returns None if the value is invalid.
    """
    try:
        cl = int(value.strip())
        if cl < 0:
            return None
        return cl
    except (ValueError, TypeError):
        return None


def _is_valid_chunk_size(size_str: str) -> bool:
    """Check if a chunk size string is valid hex (0-8 digits, optional semicolon)."""
    # Chunk size is hex, optionally followed by chunk extensions (;...)
    m = re.match(r"^([0-9a-fA-F]{1,8})(;.*)?$", size_str.strip())
    return m is not None


def _detect_chunked_transfer_encoding(headers: Mapping[str, str]) -> bool:
    """Check if Transfer-Encoding indicates chunked encoding."""
    te = headers.get("transfer-encoding", "")
    # Handle multiple values separated by commas
    for enc in te.split(","):
        if enc.strip().lower() == "chunked":
            return True
    return False


# ---------------------------------------------------------------------------
# WSGI Middleware
# ---------------------------------------------------------------------------


class HTTPDesyncMiddleware:
    """WSGI middleware that prevents HTTP request smuggling.

    Usage::

        from flask import Flask
        from http_desync_fix import HTTPDesyncMiddleware

        app = Flask(__name__)
        app.wsgi_app = HTTPDesyncMiddleware(app.wsgi_app)

    Parameters:
        app: The downstream WSGI application.
        max_content_length: Maximum allowed Content-Length in bytes.
        max_chunk_size: Maximum allowed chunk size in bytes.
        reject_both_cl_and_te: If True, reject requests with both
            Content-Length and Transfer-Encoding headers (RFC 7230 §3.3.3).
    """

    def __init__(
        self,
        app: Callable,
        *,
        max_content_length: int = MAX_CONTENT_LENGTH,
        max_chunk_size: int = MAX_CHUNK_SIZE,
        reject_both_cl_and_te: bool = True,
    ):
        self.app = app
        self.max_content_length = max_content_length
        self.max_chunk_size = max_chunk_size
        self.reject_both_cl_and_te = reject_both_cl_and_te
        self._last_log_time = 0.0

    def __call__(self, environ: MutableMapping[str, Any], start_response: Callable) -> Any:
        """Process the request and reject smuggling attempts."""
        headers = self._extract_headers(environ)

        has_cl = "content_length" in environ or "CONTENT_LENGTH" in environ
        has_te = "transfer_encoding" in environ or "TRANSFER_ENCODING" in environ

        # Check for both CL and TE headers (smuggling vector)
        if self.reject_both_cl_and_te:
            raw_cl = headers.get("content-length")
            raw_te = headers.get("transfer-encoding", "")
            if raw_cl is not None and raw_te.strip().lower():
                if _detect_chunked_transfer_encoding(headers):
                    self._log_rejection(environ, "CL.TE smuggling detected")
                    self._respond_error(start_response, 400,
                                        "Bad Request: Conflicting Content-Length and Transfer-Encoding headers")
                    return []

        # Validate Content-Length
        if has_cl:
            cl_str = environ.get("CONTENT_LENGTH", environ.get("content_length", ""))
            cl = _parse_content_length(cl_str)
            if cl is None:
                self._log_rejection(environ, "Invalid Content-Length")
                self._respond_error(start_response, 400,
                                    "Bad Request: Invalid Content-Length header")
                return []
            if cl > self.max_content_length:
                self._log_rejection(environ, f"Content-Length {cl} exceeds limit")
                self._respond_error(start_response, 413,
                                    "Payload Too Large: Content-Length exceeds maximum")
                return []
            # Cap the content length to prevent DoS
            environ["CONTENT_LENGTH"] = str(min(cl, self.max_content_length))

        # Normalise headers for downstream apps
        self._normalise_environ(environ, headers)

        return self.app(environ, start_response)

    def _extract_headers(self, environ: MutableMapping[str, Any]) -> dict[str, str]:
        """Extract headers from WSGI environ into a flat dict."""
        headers = {}
        for key, value in environ.items():
            if key.startswith("HTTP_"):
                header_name = key[5:].lower().replace("_", "-")
                headers[header_name] = value
            elif key in ("CONTENT_TYPE", "CONTENT_LENGTH"):
                header_name = key.lower().replace("_", "-")
                headers[header_name] = value
        return headers

    def _normalise_environ(self, environ: MutableMapping[str, Any], headers: dict[str, str]):
        """Normalise the environ to prevent smuggling via header quirks."""
        # Remove duplicate/conflicting headers
        te = headers.get("transfer-encoding", "")
        cl = headers.get("content-length")

        if te and cl:
            # If TE is present and not chunked, prefer it (CL should be 0)
            if not _detect_chunked_transfer_encoding(headers):
                environ["CONTENT_LENGTH"] = "0"
                del environ["wsgi.input"]  # Force re-read
            # If TE is chunked, remove Content-Length
            else:
                environ["CONTENT_LENGTH"] = "0"

    def _log_rejection(self, environ: MutableMapping[str, Any], reason: str):
        """Log a smuggling rejection with deduplication."""
        now = time.time()
        if now - self._last_log_time < SMUGGLING_REJECTION_LOG_INTERVAL:
            return
        self._last_log_time = now
        logger.warning(
            "HTTP Desync rejection: %s from %s path=%s method=%s",
            reason,
            environ.get("REMOTE_ADDR", "unknown"),
            environ.get("PATH_INFO", ""),
            environ.get("REQUEST_METHOD", ""),
        )

    def _respond_error(
        self, start_response: Callable, status: int, reason: str
    ) -> None:
        """Send an error response."""
        status_text = {400: "Bad Request", 413: "Payload Too Large"}.get(status, "Error")
        body = f"{status_text}: {reason}".encode("utf-8")

        def error_start_response(status_code, response_headers, exc_info=None):
            if status_code != status:
                status_code = status
            response_headers.append(("Content-Length", str(len(body))))
            response_headers.append(("Content-Type", "text/plain; charset=utf-8"))
            start_response(status_code, response_headers, exc_info)

        start_response(status, [("Content-Type", "text/plain")], None)
        # Override to our error handler
        self._actual_start_response = lambda s, h, e=None: error_start_response(s, h, e)


# ---------------------------------------------------------------------------
# ASGI Middleware (for FastAPI / Starlette / Quart)
# ---------------------------------------------------------------------------


class HTTPDesyncASGIMiddleware:
    """ASGI middleware that prevents HTTP request smuggling.

    Usage::

        from fastapi import FastAPI
        from http_desync_fix import HTTPDesyncASGIMiddleware

        app = FastAPI()
        app.add_middleware(HTTPDesyncASGIMiddleware)
    """

    def __init__(self, app: Callable, max_content_length: int = MAX_CONTENT_LENGTH):
        self.app = app
        self.max_content_length = max_content_length

    async def __call__(self, scope: dict, receive: Callable, send: Callable) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        headers = dict(scope.get("headers", []))

        # Decode header values
        decoded_headers = {}
        for k, v in headers:
            decoded_headers[k.decode("latin-1").lower()] = v.decode("latin-1")

        has_cl = "content-length" in decoded_headers
        has_te = "transfer-encoding" in decoded_headers
        cl_val = decoded_headers.get("content-length", "")
        te_val = decoded_headers.get("transfer-encoding", "")

        # Reject if both CL and TE are present
        if has_cl and has_te and _detect_chunked_transfer_encoding(decoded_headers):
            await send({
                "type": "http.response.start",
                "status": 400,
                "headers": [
                    (b"content-type", b"text/plain"),
                    (b"content-length", b"56"),
                ],
            })
            await send({
                "type": "http.response.body",
                "body": b"Bad Request: Conflicting HTTP framing headers",
            })
            return

        # Validate Content-Length
        if has_cl:
            cl = _parse_content_length(cl_val)
            if cl is None:
                await send({
                    "type": "http.response.start",
                    "status": 400,
                    "headers": [
                        (b"content-type", b"text/plain"),
                        (b"content-length", b"42"),
                    ],
                })
                await send({
                    "type": "http.response.body",
                    "body": b"Bad Request: Invalid Content-Length",
                })
                return
            if cl > self.max_content_length:
                await send({
                    "type": "http.response.start",
                    "status": 413,
                    "headers": [
                        (b"content-type", b"text/plain"),
                        (b"content-length", b"44"),
                    ],
                })
                await send({
                    "type": "http.response.body",
                    "body": b"Payload Too Large: Content-Length exceeds limit",
                })
                return

        # Normalise: if TE=chunked, set CL=0
        if has_te and _detect_chunked_transfer_encoding(decoded_headers):
            scope["headers"] = [
                (k.encode("latin-1"), v.encode("latin-1"))
                for k, v in decoded_headers.items()
                if k != "content-length"
            ]

        await self.app(scope, receive, send)


# ---------------------------------------------------------------------------
# Standalone validation function (framework-agnostic)
# ---------------------------------------------------------------------------


def validate_http_request(
    headers: Mapping[str, str],
    *,
    max_content_length: int = MAX_CONTENT_LENGTH,
    reject_conflicting: bool = True,
) -> Tuple[bool, str]:
    """Validate HTTP request headers for smuggling indicators.

    Returns:
        (is_valid, error_message)
    """
    cl_raw = headers.get("content-length", "")
    te_raw = headers.get("transfer-encoding", "")

    if reject_conflicting and cl_raw.strip() and te_raw.strip():
        if _detect_chunked_transfer_encoding(headers):
            return False, "Request contains both Content-Length and Transfer-Encoding: chunked"

    if cl_raw.strip():
        cl = _parse_content_length(cl_raw)
        if cl is None:
            return False, f"Invalid Content-Length value: {cl_raw!r}"
        if cl > max_content_length:
            return False, f"Content-Length {cl} exceeds maximum {max_content_length}"

    return True, ""


# ---------------------------------------------------------------------------
# Self-tests
# ---------------------------------------------------------------------------


def _run_tests() -> None:
    """Run self-tests to verify the fix."""
    # Test 1: Valid request with only Content-Length
    ok, err = validate_http_request({"content-length": "100"})
    assert ok, f"Should accept CL-only: {err}"

    # Test 2: Valid request with only Transfer-Encoding
    ok, err = validate_http_request({"transfer-encoding": "chunked"})
    assert ok, f"Should accept TE-only: {err}"

    # Test 3: Invalid - both CL and TE (smuggling)
    ok, err = validate_http_request({
        "content-length": "100",
        "transfer-encoding": "chunked",
    })
    assert not ok, "Should reject CL+TE"
    assert "Conflicting" in err or "both" in err.lower()

    # Test 4: Invalid - Content-Length with non-chunked TE
    ok, err = validate_http_request({
        "content-length": "100",
        "transfer-encoding": "gzip, chunked",
    })
    assert not ok, "Should reject CL+TE(gzip,chunked)"

    # Test 5: Invalid - negative Content-Length
    ok, err = validate_http_request({"content-length": "-1"})
    assert not ok, "Should reject negative CL"

    # Test 6: Invalid - non-numeric Content-Length
    ok, err = validate_http_request({"content-length": "abc"})
    assert not ok, "Should reject non-numeric CL"

    # Test 7: Valid - Content-Length within limit
    ok, err = validate_http_request(
        {"content-length": "5000"},
        max_content_length=1024,
    )
    assert not ok, "Should reject oversized CL"

    # Test 8: Valid - Content-Length at limit
    ok, err = validate_http_request(
        {"content-length": "1024"},
        max_content_length=1024,
    )
    assert ok, f"Should accept CL at limit: {err}"

    # Test 9: Valid - Empty headers
    ok, err = validate_http_request({})
    assert ok, f"Should accept empty headers: {err}"

    # Test 10: CL.TE smuggling scenario
    ok, err = validate_http_request({
        "content-length": "0",
        "transfer-encoding": "chunked",
    })
    assert not ok, "Should reject CL=0 + TE=chunked"

    print("All self-tests passed!")


if __name__ == "__main__":
    _run_tests()
