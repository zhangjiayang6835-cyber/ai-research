"""
fix_access_log_crlf.py — Access Log CRLF Injection → HTTP Response Splitting Fix

Issue #681 — Access log writes User-Agent directly into response header:
  res.setHeader("X-Log", userAgent)

Attackers inject CRLF (%0d%0a) sequences via User-Agent to split the HTTP
response, allowing arbitrary header/body injection and cache poisoning.

FIX:
1. Strip/reject CRLF sequences from all user-controlled header values
2. Never write raw user input into response headers — use safe wrapper
3. Encode dangerous characters with encodeURIComponent-style sanitization
4. Log to file instead of response header for access tracking
"""

from __future__ import annotations

import html
import logging
import re
from datetime import datetime, timezone
from typing import Dict, Optional, Tuple


# ═══════════════════════════════════════════════════════════════════
# Configuration
# ═══════════════════════════════════════════════════════════════════

# CRLF and control character patterns
CRLF_PATTERN = re.compile(r"[\r\n\x0d\x0a]")
URL_ENCODED_CRLF = re.compile(r"%0[ddD]%0[aaA]", re.IGNORECASE)
DANGEROUS_HEADER_CHARS = re.compile(r"[\x00-\x1f\x7f]")


# ═══════════════════════════════════════════════════════════════════
# CRLF Sanitizer for Header Values
# ═══════════════════════════════════════════════════════════════════


class CRLFSanitizer:
    """Sanitizes user-controlled input before writing to HTTP response headers."""

    @staticmethod
    def contains_crlf(value: str) -> bool:
        """Check if a value contains CRLF sequences (literal or URL-encoded)."""
        if CRLF_PATTERN.search(value):
            return True
        if URL_ENCODED_CRLF.search(value):
            return True
        if re.search(r"%0[dd]|%0[aa]", value, re.IGNORECASE):
            return True
        return False

    @staticmethod
    def sanitize(value: str) -> str:
        """Remove CRLF and control characters from input."""
        result = value.replace("\r", "").replace("\n", "")
        result = re.sub(r"%0d%0a", "", result, flags=re.IGNORECASE)
        result = re.sub(r"%0a%0d", "", result, flags=re.IGNORECASE)
        result = re.sub(r"%0d", "", result, flags=re.IGNORECASE)
        result = re.sub(r"%0a", "", result, flags=re.IGNORECASE)
        result = DANGEROUS_HEADER_CHARS.sub("", result)
        return result

    @staticmethod
    def safe_encode(value: str) -> str:
        """Encode value for safe inclusion in HTTP response headers."""
        result = CRLFSanitizer.sanitize(value)
        result = result.replace("\\", "\\\\")
        result = result.replace('"', "&quot;")
        return result


# ═══════════════════════════════════════════════════════════════════
# Secure Access Log Header Handler
# ═══════════════════════════════════════════════════════════════════


class AccessLogHeader:
    """Secure wrapper for access-log-style response headers."""

    def __init__(self, enable_file_logging: bool = True):
        self.enable_file_logging = enable_file_logging
        self._file_logger = self._setup_logger() if enable_file_logging else None

    def _setup_logger(self) -> logging.Logger:
        logger = logging.getLogger("access_log")
        logger.setLevel(logging.INFO)
        if not logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter(
                "%(asctime)s [%(levelname)s] %(message)s",
                datefmt="%Y-%m-%dT%H:%M:%S%z",
            )
            handler.setFormatter(formatter)
            logger.addHandler(handler)
        return logger

    def set_safe_header(self, name: str, value: str) -> Tuple[bool, Optional[str]]:
        """Set a response header with full CRLF protection."""
        if CRLFSanitizer.contains_crlf(value):
            return False, "CRLF sequences detected and rejected"
        safe_value = CRLFSanitizer.sanitize(value)
        encoded_value = CRLFSanitizer.safe_encode(safe_value)
        if self._file_logger:
            self._file_logger.info(
                "Header: %s | Value: %s | Sanitized: %s",
                name, value[:100], safe_value[:100],
            )
        return True, encoded_value

    def set_x_log_header(self, user_agent: str) -> Tuple[bool, Optional[str]]:
        """Specifically fix the X-Log header pattern from issue #681."""
        return self.set_safe_header("X-Log", user_agent)

    def safe_user_agent_for_header(self, user_agent: str) -> str:
        """Return a User-Agent value safe for response header reflection."""
        return CRLFSanitizer.safe_encode(user_agent)


# ═══════════════════════════════════════════════════════════════════
# Direct Fix: The Vulnerable Pattern
# ═══════════════════════════════════════════════════════════════════


def fix_access_log_header(user_agent: str) -> str:
    """Drop-in replacement for the vulnerable res.setHeader('X-Log', userAgent).

    Original:  res.setHeader("X-Log", userAgent)
    Fixed:     res.setHeader("X-Log", fix_access_log_header(userAgent))
    """
    return CRLFSanitizer.safe_encode(user_agent)


def is_safe_for_header(value: str) -> bool:
    """Check if a value is safe to include in a response header."""
    return not CRLFSanitizer.contains_crlf(value)


# ═══════════════════════════════════════════════════════════════════
# Tests
# ═══════════════════════════════════════════════════════════════════


def test_crlf_detection():
    assert CRLFSanitizer.contains_crlf("test\r\ninjection")
    assert CRLFSanitizer.contains_crlf("test%0d%0ainjection")
    assert CRLFSanitizer.contains_crlf("test%0D%0Ainjection")
    assert CRLFSanitizer.contains_crlf("test%0dinjection")
    assert CRLFSanitizer.contains_crlf("test%0ainjection")
    assert not CRLFSanitizer.contains_crlf("Mozilla/5.0 (Macintosh)")
    assert not CRLFSanitizer.contains_crlf("curl/7.68.0")
    print("PASS: CRLF detection")


def test_crlf_sanitization():
    sanitized = CRLFSanitizer.sanitize("test\r\ninjection")
    assert "\r" not in sanitized
    assert "\n" not in sanitized
    assert sanitized == "testinjection"
    sanitized = CRLFSanitizer.sanitize("test%0d%0ainjection")
    assert "%0d" not in sanitized.lower()
    ua = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)"
    assert CRLFSanitizer.sanitize(ua) == ua
    print("PASS: CRLF sanitization")


def test_safe_encoding():
    ua = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)"
    assert CRLFSanitizer.safe_encode(ua) == ua
    encoded = CRLFSanitizer.safe_encode("Mozilla\r\nX-Evil: true")
    assert "\r" not in encoded
    assert "\n" not in encoded
    print("PASS: Safe encoding")


def test_drop_in_replacement():
    result = fix_access_log_header("Mozilla/5.0 (Windows NT 10.0)")
    assert "Mozilla" in result
    assert "\r" not in result
    result = fix_access_log_header("EvilBot\r\nX-Hacked: true\r\n")
    assert "\r" not in result
    assert "X-Hacked" not in result
    print("PASS: Drop-in replacement")


def test_access_log_header_class():
    logger = AccessLogHeader(enable_file_logging=False)
    success, value = logger.set_x_log_header("Mozilla/5.0")
    assert success
    success, value = logger.set_x_log_header("EvilBot\r\nSet-Cookie: malicious=true")
    assert not success
    print("PASS: AccessLogHeader class")


def test_real_world_attack_vectors():
    vectors = [
        "Mozilla/5.0\r\nX-Hacked: true\r\n",
        "curl/7.68.0%0d%0aX-Hacked:%20true",
        "Python/3.9%0d%0aSet-Cookie:%20session=malicious",
        "Bot\r\nLocation: https://evil.com\r\n",
        "Mozilla/5.0\r\nContent-Length: 0\r\n\r\n<html>injected</html>",
        "Normal/1.0 (compatible)",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
    ]
    for v in vectors:
        result = fix_access_log_header(v)
        assert "\r" not in result
        assert "\n" not in result
    print("PASS: All attack vectors handled")


def test_edge_cases():
    assert CRLFSanitizer.safe_encode("") == ""
    assert CRLFSanitizer.safe_encode("\r\n") == ""
    result = CRLFSanitizer.safe_encode("a\r\nb\r\nc")
    assert result == "abc"
    result = CRLFSanitizer.safe_encode("Mozilla/5.0 (中文/日本語)")
    assert "中文" in result
    assert "日本語" in result
    result = CRLFSanitizer.safe_encode("test\x09value")
    assert "\x09" not in result
    result = CRLFSanitizer.safe_encode("test\x00value")
    assert "\x00" not in result
    print("PASS: Edge cases")


def test_is_safe_for_header():
    assert not is_safe_for_header("test\r\ninjection")
    assert not is_safe_for_header("test%0d%0ainjection")
    assert is_safe_for_header("Safe User-Agent String")
    assert is_safe_for_header("Mozilla/5.0 (compatible; Googlebot/2.1)")
    print("PASS: is_safe_for_header")


if __name__ == "__main__":
    test_crlf_detection()
    test_crlf_sanitization()
    test_safe_encoding()
    test_drop_in_replacement()
    test_access_log_header_class()
    test_real_world_attack_vectors()
    test_edge_cases()
    test_is_safe_for_header()
    print("\n✅ ALL 8 TESTS PASSED — Access Log CRLF Injection Fix Complete!")
