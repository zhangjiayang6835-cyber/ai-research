"""Tests for RequestSanitizer — CWE-444 & CWE-524 coverage."""
from src.security.request_sanitizer import RequestSanitizer


class TestCLTEConflict:
    """RFC 7230 §3.3.3: Requests with both CL and TE must be rejected."""

    def test_rejects_cl_and_te_together(self):
        s = RequestSanitizer()
        ok, err = s.validate({
            b"content-length": b"44",
            b"transfer-encoding": b"chunked",
            b"host": b"example.com",
        })
        assert not ok
        assert "400" in err

    def test_allows_cl_only(self):
        s = RequestSanitizer()
        ok, _ = s.validate({
            b"content-length": b"13",
            b"host": b"example.com",
        })
        assert ok

    def test_allows_te_only(self):
        s = RequestSanitizer()
        ok, _ = s.validate({
            b"transfer-encoding": b"chunked",
            b"host": b"example.com",
        })
        assert ok


class TestContentLength:
    """Content-Length header edge cases."""

    def test_rejects_leading_zeros(self):
        s = RequestSanitizer()
        ok, _ = s.validate({b"content-length": b"044", b"host": b"x"})
        assert not ok

    def test_rejects_non_numeric(self):
        s = RequestSanitizer()
        ok, _ = s.validate({b"content-length": b"abc", b"host": b"x"})
        assert not ok

    def test_accepts_zero_length(self):
        s = RequestSanitizer()
        ok, _ = s.validate({b"content-length": b"0", b"host": b"x"})
        assert ok


class TestTransferEncoding:
    """Transfer-Encoding header validation."""

    def test_rejects_identity_coding(self):
        s = RequestSanitizer()
        ok, _ = s.validate({
            b"transfer-encoding": b"identity",
            b"host": b"x",
        })
        assert not ok

    def test_rejects_empty_value(self):
        s = RequestSanitizer()
        ok, _ = s.validate({
            b"transfer-encoding": b"",
            b"host": b"x",
        })
        assert not ok


class TestHeaderValueValidation:
    """Header values must not carry control characters."""

    def test_rejects_crlf_in_header_value(self):
        s = RequestSanitizer()
        ok, err = s.validate({
            b"host": b"example.com\r\nX-Evil: yes",
            b"accept": b"text/html",
        })
        assert not ok
        assert "Invalid header value" in err


class TestDuplicateHeaders:
    """Single-value headers must not appear multiple times."""

    def test_rejects_double_content_length(self):
        s = RequestSanitizer()
        ok, _ = s.validate({
            b"content-length": b"10",
            b"host": b"x",
        })
        assert ok
        # Force duplicate via case variation
        ok2, _ = s.validate({
            b"Content-Length": b"10",
            b"content-length": b"20",
            b"host": b"x",
        })
        assert not ok2


class TestCacheKey:
    """Cache key must be deterministic and hop-by-hop agnostic."""

    def test_stable_cache_key(self):
        s = RequestSanitizer()
        headers = {b"host": b"example.com", b"accept": b"text/html"}
        assert s.cache_key(headers) == s.cache_key(headers)

    def test_hop_by_hop_stripped(self):
        s = RequestSanitizer()
        h1 = {
            b"host": b"x",
            b"transfer-encoding": b"chunked",
            b"connection": b"keep-alive",
        }
        h2 = {
            b"host": b"x",
            b"transfer-encoding": b"gzip",
            b"connection": b"close",
        }
        assert s.cache_key(h1) == s.cache_key(h2)


class TestSanitizeHeaders:
    """Forwarding-safe sanitization must drop hop-by-hop headers."""

    def test_sanitizes_forward_headers(self):
        s = RequestSanitizer()
        cleaned = s.sanitize_headers({
            b"Host": b"example.com",
            b"Connection": b"keep-alive",
            b"Accept": b"text/html",
        })
        assert cleaned == {
            b"host": b"example.com",
            b"accept": b"text/html",
        }


class TestHeaderNameValidation:
    """RFC 7230 §3.2.6: Header name character constraints."""

    def test_rejects_newline_in_header_name(self):
        s = RequestSanitizer()
        ok, _ = s.validate({
            b"Host": b"example.com",
            b"X-Evil\r\nInjected": b"payload",
        })
        assert not ok
