"""
Fix for Issue #743 — CL.TE HTTP Request Smuggling

Vulnerability
-------------
Frontend nginx uses Content-Length while backend uses Transfer-Encoding: chunked.
Attacker crafts ambiguous requests, causing request smuggling and cache poisoning.

Fix
---
- Reject requests with both Content-Length and Transfer-Encoding
- Normalize Transfer-Encoding header values
- Prefer HTTP/2 to eliminate ambiguity
"""

import re


class HTTPSmugglingPrevention:
    """Middleware to detect and block HTTP request smuggling attempts."""

    @classmethod
    def validate_headers(cls, headers: dict) -> tuple:
        """Validate HTTP headers for smuggling attempts."""
        has_cl = "content-length" in {k.lower() for k in headers}
        has_te = "transfer-encoding" in {k.lower() for k in headers}

        if has_cl and has_te:
            return False, "Request has both Content-Length and Transfer-Encoding"

        if has_te:
            te_value = headers.get("Transfer-Encoding", headers.get("transfer-encoding", ""))
            if "," in te_value:
                return False, "Multiple Transfer-Encoding values not allowed"
            if re.search(r'chu[nk]+ed', te_value, re.IGNORECASE) and \
               not re.fullmatch(r'\s*chunked\s*', te_value, re.IGNORECASE):
                return False, "Malformed Transfer-Encoding value"

        return True, None


NGINX_CONFIG = """
# CL.TE Request Smuggling Prevention
server {
    # Reject requests with both Content-Length and Transfer-Encoding
    if ($http_transfer_encoding ~* "chunked") {
        set $smuggling_check "${http_content_length}";
    }
    if ($smuggling_check != "") {
        return 400 "Bad Request: Ambiguous Content-Length/Transfer-Encoding";
    }
    # Normalize Transfer-Encoding
    proxy_set_header Transfer-Encoding "";
    # Prefer HTTP/2 for upstream
    proxy_http_version 2.0;
}
"""


if __name__ == "__main__":
    tests = [
        ({"Content-Length": "100"}, True),
        ({"Transfer-Encoding": "chunked"}, True),
        ({"Content-Length": "100", "Transfer-Encoding": "chunked"}, False),
        ({"Transfer-Encoding": "chuunked"}, False),
    ]
    for headers, expected in tests:
        valid, msg = HTTPSmugglingPrevention.validate_headers(headers)
        status = "PASS" if valid == expected else "FAIL"
        print(f"{status}: {list(headers.keys())} -> valid={valid}")
    print("Nginx config:")
    print(NGINX_CONFIG)