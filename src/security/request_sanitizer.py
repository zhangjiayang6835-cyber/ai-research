"""
HTTP Request Sanitizer — CWE-444 / CWE-524 Mitigation
======================================================
OWASP-compliant middleware for HTTP request smuggling detection
and web cache poisoning prevention.

Reference: https://portswigger.net/web-security/request-smuggling
"""

import re
from hashlib import sha256
from typing import Optional, Tuple


class RequestSanitizer:
    """Validates HTTP requests for smuggling & cache poisoning indicators."""

    _HOP_BY_HOP = {
        b"connection", b"keep-alive", b"proxy-authenticate",
        b"proxy-authorization", b"te", b"trailers",
        b"transfer-encoding", b"upgrade",
    }

    @staticmethod
    def _has_control_bytes(value: bytes) -> bool:
        return any(token in value for token in (b"\r", b"\n", b"\x00"))

    def validate(self, headers: dict) -> Tuple[bool, Optional[str]]:
        """
        Validate request headers for security issues.

        Returns:
            (is_valid, error_message) — error_message is None if valid.
        """
        # ── CL/TE conflict (RFC 7230 §3.3.3) ──
        has_cl = any(k.lower() == b"content-length" for k in headers)
        has_te = any(k.lower() == b"transfer-encoding" for k in headers)
        if has_cl and has_te:
            return False, "HTTP 400: CL/TE conflict (RFC 7230 §3.3.3)"

        # ── Content-Length validation ──
        for key, value in headers.items():
            if self._has_control_bytes(key):
                return False, "HTTP 400: Invalid header name: control characters"
            if self._has_control_bytes(value):
                return False, (
                    "HTTP 400: Invalid header value: "
                    f"'{key.decode(errors='replace')}'"
                )
            if key.lower() == b"content-length":
                cl = value.strip()
                if not cl.isdigit():
                    return False, "HTTP 400: Content-Length not numeric"
                if len(cl) > 1 and cl.startswith(b"0"):
                    return False, "HTTP 400: Content-Length has leading zeros"
                if int(cl) < 0:
                    return False, "HTTP 400: Content-Length negative"

        # ── Transfer-Encoding validation ──
        for key, value in headers.items():
            if key.lower() == b"transfer-encoding":
                tv = value.strip().lower()
                if tv in {b"", b"identity"}:
                    return False, "HTTP 400: Invalid Transfer-Encoding"

        # ── Duplicate single-value header detection ──
        singles = {b"content-length", b"content-type",
                   b"host", b"transfer-encoding"}
        seen = set()
        for key in headers:
            kl = key.lower()
            if kl in singles:
                if kl in seen:
                    return False, (
                        f"HTTP 400: Duplicate header: "
                        f"'{key.decode(errors='replace')}'"
                    )
                seen.add(kl)

        # ── Header name character check (RFC 7230 §3.2.6) ──
        for key in headers:
            if not re.match(rb"^[a-zA-Z0-9!#$%%&'*+.^_`|~-]+$", key):
                return False, (
                    "HTTP 400: Invalid header name: "
                    f"'{key.decode(errors='replace')}'"
                )

        return True, None

    def cache_key(self, headers: dict) -> str:
        """
        Build a deterministic cache key.

        Strips hop-by-hop headers (RFC 7230 §6.1) and normalizes
        key ordering to prevent cache poisoning via header manipulation.
        """
        sanitized = self.sanitize_headers(headers)
        normalized = {
            k.decode(errors="replace"): v.decode(errors="replace")
            for k, v in sorted(sanitized.items(), key=lambda kv: kv[0].lower())
        }
        payload = repr(sorted(normalized.items())).encode()
        return sha256(payload).hexdigest()

    def sanitize_headers(self, headers: dict) -> dict:
        """
        Return a forwarding-safe header mapping.

        Invalid inputs are rejected instead of being normalized into a
        request that could be split or smuggled downstream.
        """
        ok, err = self.validate(headers)
        if not ok:
            raise ValueError(err or "HTTP 400: Invalid headers")

        return {
            key.lower(): value
            for key, value in headers.items()
            if key.lower() not in self._HOP_BY_HOP
        }
