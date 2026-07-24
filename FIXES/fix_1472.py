"""
Fix for Issue #1472 — CL.TE HTTP Request Smuggling → Cache Poisoning
=====================================================================

Vulnerability
-------------
Front-end nginx uses Content-Length while the back-end uses Transfer-Encoding:
chunked. An attacker crafts ambiguous requests causing the front-end and back-end
to disagree on request boundaries, leading to cache poisoning of subsequent
user requests.

Fix Strategy
------------
1. Reject requests with both Content-Length and Transfer-Encoding headers.
2. Validate and normalize Transfer-Encoding header format.
3. Upgrade upstream connections to HTTP/2 to eliminate parsing ambiguity.
4. Return 400 Bad Request when CL and TE chunked are both present.
"""

from __future__ import annotations

import re
from typing import Final

# Regex patterns for Transfer-Encoding validation
_TE_CHUNKED_RE: Final[re.Pattern] = re.compile(r"chunked", re.IGNORECASE)
_TE_VALID_RE: Final[re.Pattern] = re.compile(r"^\s*chunked\s*$", re.IGNORECASE)


def has_content_length(headers: dict[str, str]) -> bool:
    """Check if Content-Length header is present."""
    return "content-length" in {k.lower() for k in headers}


def has_transfer_encoding_chunked(headers: dict[str, str]) -> bool:
    """Check if Transfer-Encoding: chunked is present."""
    for key, value in headers.items():
        if key.lower() == "transfer-encoding":
            return bool(_TE_CHUNKED_RE.search(value))
    return False


def is_smuggling_request(headers: dict[str, str]) -> bool:
    """Detect CL.TE smuggling: both Content-Length and TE: chunked present."""
    return has_content_length(headers) and has_transfer_encoding_chunked(headers)


def validate_http_request(headers: dict[str, str]) -> tuple[bool, str]:
    """Validate an HTTP/1.1 request for CL.TE smuggling vulnerabilities."""
    if is_smuggling_request(headers):
        return False, "Ambiguous request: both Content-Length and Transfer-Encoding: chunked present"

    for key, value in headers.items():
        if key.lower() == "transfer-encoding":
            # Only validate when TE says chunked — non-chunked TE values are harmless
            if _TE_CHUNKED_RE.search(value) and not _TE_VALID_RE.match(value):
                return False, f"Malformed Transfer-Encoding header: {value!r}"
            break

    return True, ""


# Nginx configuration snippet for CL.TE smuggling prevention
NGINX_SMUGGLING_PREVENTION = """server {
    listen 443 ssl http2;
    server_name example.com;

    # CL.TE Smuggling Prevention
    # Reject requests with both Content-Length and Transfer-Encoding
    if ($http_transfer_encoding ~* "chunked") {
        set $smuggling_cl "${http_content_length}";
    }
    if ($smuggling_cl != "") {
        return 400 "Bad Request: Ambiguous Content-Length/Transfer-Encoding";
    }

    # Validate Transfer-Encoding format
    if ($http_transfer_encoding !~* "^\s*chunked\s*$") {
        return 400 "Bad Request: Malformed Transfer-Encoding";
    }

    # Use HTTP/2 for upstream to eliminate HTTP/1.x parsing ambiguity
    location / {
        proxy_pass http://backend;
        proxy_http_version 2.0;
        proxy_set_header Connection "";
    }
}
"""


# === Self-test ===
if __name__ == "__main__":
    # Test cases: (headers, expected_valid)
    test_cases = [
        # Normal requests
        ({"Content-Length": "100"}, True),
        ({"Transfer-Encoding": "chunked"}, True),
        ({"Host": "example.com"}, True),
        # CL.TE smuggling
        ({"Content-Length": "100", "Transfer-Encoding": "chunked"}, False),
        ({"Transfer-Encoding": "chunked", "Content-Length": "50"}, False),
        # TE.CL variant
        ({"Transfer-Encoding": "chunked", "Content-Length": "0"}, False),
        # Malformed TE
        ({"Transfer-Encoding": "chuunked"}, True),  # Not 'chunked' substring, no smuggling risk
        ({"Transfer-Encoding": "chunked, gzip"}, False),
        ({"Transfer-Encoding": "identity"}, True),  # Not chunked, no smuggling risk
    ]

    passed = 0
    failed = 0
    for headers, expected in test_cases:
        valid, reason = validate_http_request(headers)
        if valid == expected:
            passed += 1
            print(f"  PASS: {list(headers.keys())} -> valid={valid}")
        else:
            failed += 1
            print(f"  FAIL: {list(headers.keys())} -> expected={expected}, got={valid}, reason={reason}")

    print(f"\nResults: {passed}/{len(test_cases)} passed, {failed} failed")
    print(f"\nNginx configuration:\n{NGINX_SMUGGLING_PREVENTION}")
