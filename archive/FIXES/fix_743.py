"""
Fix for Issue #743 — CL.TE HTTP Request Smuggling → Cache Poisoning
=====================================================================

Vulnerability
-------------
The front-end (nginx) uses Content-Length while the back-end uses Transfer-Encoding:
chunked. An attacker crafts ambiguous requests, causing front-end and back-end
to disagree on request boundaries, poisoning the cache.

Fix Strategy
------------
1. Reject requests with both Content-Length and Transfer-Encoding headers.
2. Normalize Transfer-Encoding parsing to reject malformed values.
3. Use HTTP/2 to eliminate HTTP/1.x parsing ambiguity entirely.
"""

from __future__ import annotations

import re
from typing import Final

_TE_VALID_RE: Final[re.Pattern] = re.compile(r"^\s*chunked\s*$", re.IGNORECASE)
_TE_CHUNKED_RE: Final[re.Pattern] = re.compile(r"chunked", re.IGNORECASE)


def has_transfer_encoding_chunked(headers: dict[str, str]) -> bool:
    te = headers.get("Transfer-Encoding", "")
    return bool(_TE_CHUNKED_RE.search(te))


def has_content_length(headers: dict[str, str]) -> bool:
    return "Content-Length" in headers


def is_smuggling_request(headers: dict[str, str]) -> bool:
    """Detect CL.TE smuggling: both Content-Length and Transfer-Encoding: chunked."""
    return has_content_length(headers) and has_transfer_encoding_chunked(headers)


def validate_http_request(headers: dict[str, str]) -> tuple[bool, str]:
    """Validate an HTTP/1.1 request for smuggling vulnerabilities."""
    if is_smuggling_request(headers):
        return False, "Ambiguous request: both Content-Length and Transfer-Encoding: chunked present"
    te = headers.get("Transfer-Encoding", "")
    if te and not _TE_VALID_RE.match(te):
        return False, f"Malformed Transfer-Encoding header: {te!r}"
    return True, ""


class SmugglingProtectionMiddleware:
    """WSGI middleware that rejects CL.TE smuggling requests."""

    def __init__(self, app):
        self.app = app

    def __call__(self, environ, start_response):
        headers = {}
        for key, value in environ.items():
            if key.startswith("HTTP_"):
                header_name = key[5:].replace("_", "-").title()
                headers[header_name] = value
        valid, reason = validate_http_request(headers)
        if not valid:
            start_response("400 Bad Request", [("Content-Type", "text/plain")])
            return [reason.encode()]
        return self.app(environ, start_response)
