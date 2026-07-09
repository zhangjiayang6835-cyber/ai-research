"""
fix_clickjacking_crypto.py — Clickjacking → Crypto Withdrawal Protection

Issue #727 — Asset withdrawal page lacks X-Frame-Options / CSP frame-ancestors,
allowing attackers to overlay transparent iframes and trick users into clicking
confirm-withdrawal buttons.

FIX:
1. Add X-Frame-Options: DENY to all responses
2. Add Content-Security-Policy: frame-ancestors 'none'
3. Add double-confirmation for critical operations (withdraw, transfer, etc.)
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import time
from typing import Any, Dict, List, Optional, Tuple


# ═══════════════════════════════════════════════════════════════════
# Configuration
# ═══════════════════════════════════════════════════════════════════

SECURE_HEADERS = {
    "X-Frame-Options": "DENY",
    "Content-Security-Policy": "frame-ancestors 'none'",
    "X-Content-Type-Options": "nosniff",
}

CRITICAL_ACTIONS = {"withdraw", "transfer", "send", "approve", "delegate"}


# ═══════════════════════════════════════════════════════════════════
# 1. Secure Headers Middleware
# ═══════════════════════════════════════════════════════════════════


class SecureHeadersMiddleware:
    """WSGI middleware that adds anti-clickjacking headers to all responses."""

    def __init__(self, app, extra_headers: Optional[Dict[str, str]] = None):
        self.app = app
        self.headers = {**SECURE_HEADERS, **(extra_headers or {})}

    def __call__(self, environ, start_response):
        def secure_start_response(status, headers, exc_info=None):
            for name, value in self.headers.items():
                headers.append((name, value))
            return start_response(status, headers, exc_info)

        return self.app(environ, secure_start_response)


# ═══════════════════════════════════════════════════════════════════
# 2. Response Header Fix
# ═══════════════════════════════════════════════════════════════════


def add_anti_clickjacking_headers(
    headers: List[Tuple[str, str]]
) -> List[Tuple[str, str]]:
    """Add anti-clickjacking headers to a response header list."""
    header_dict = dict(headers)
    header_dict["X-Frame-Options"] = "DENY"
    header_dict["Content-Security-Policy"] = "frame-ancestors 'none'"
    return list(header_dict.items())


def set_anti_clickjacking_headers(response: Any) -> Any:
    """Set anti-clickjacking headers on a response object."""
    if hasattr(response, "headers"):
        if hasattr(response.headers, "__setitem__"):
            response.headers["X-Frame-Options"] = "DENY"
            response.headers["Content-Security-Policy"] = "frame-ancestors 'none'"
            response.headers["X-Content-Type-Options"] = "nosniff"
    return response


# ═══════════════════════════════════════════════════════════════════
# 3. Double Confirmation for Critical Operations
# ═══════════════════════════════════════════════════════════════════


class DoubleConfirmation:
    """Provides double-confirmation mechanism for critical operations."""

    def __init__(self, secret_key: Optional[str] = None):
        self.secret_key = secret_key or os.urandom(32).hex()
        self._pending: Dict[str, dict] = {}

    def _generate_token(self, action: str, user_id: str, amount: float) -> str:
        """Generate a time-limited confirmation token."""
        payload = {
            "action": action,
            "user_id": user_id,
            "amount": amount,
            "timestamp": int(time.time()),
            "nonce": os.urandom(8).hex(),
        }
        # Store the full payload with the original nonce for verification
        payload_bytes = json.dumps(payload, sort_keys=True).encode()
        signature = hmac.new(
            self.secret_key.encode(), payload_bytes, hashlib.sha256
        ).hexdigest()[:16]
        token = f"{signature}:{payload['timestamp']}:{payload['nonce']}"
        self._pending[token] = payload
        return token

    def _verify_signature(self, token: str) -> bool:
        """Verify the token signature against stored payload."""
        if token not in self._pending:
            return False
        payload = self._pending[token]
        payload_bytes = json.dumps(payload, sort_keys=True).encode()
        expected_sig = hmac.new(
            self.secret_key.encode(), payload_bytes, hashlib.sha256
        ).hexdigest()[:16]
        actual_sig = token.split(":")[0]
        return hmac.compare_digest(expected_sig, actual_sig)

    def request_confirmation(
        self, action: str, user_id: str, amount: float
    ) -> Dict[str, Any]:
        """Request double confirmation for a critical operation."""
        token = self._generate_token(action, user_id, amount)
        return {
            "type": "double_confirmation",
            "message": (
                f"⚠️ CRITICAL ACTION: {action.upper()}\n"
                f"Amount: ${amount:.2f}\n"
                f"Please confirm this operation by clicking the confirm button."
            ),
            "confirm_token": token,
            "expires_in": 300,
        }

    def confirm(self, token: str) -> Tuple[bool, str]:
        """Confirm a pending critical operation."""
        if token not in self._pending:
            return False, "Invalid or expired confirmation token"

        payload = self._pending[token]
        elapsed = int(time.time()) - payload["timestamp"]

        if elapsed > 300:
            del self._pending[token]
            return False, "Confirmation token expired (5 minute limit)"

        if not self._verify_signature(token):
            del self._pending[token]
            return False, "Token signature mismatch"

        del self._pending[token]
        return True, f"{payload['action']} confirmed for user {payload['user_id']}"

    def cleanup_expired(self):
        """Remove expired tokens."""
        now = int(time.time())
        expired = [
            t for t, p in self._pending.items()
            if now - p["timestamp"] > 300
        ]
        for t in expired:
            del self._pending[t]


# ═══════════════════════════════════════════════════════════════════
# 4. Direct Fix
# ═══════════════════════════════════════════════════════════════════


def fix_withdrawal_page_security(response_headers: Dict[str, str]) -> Dict[str, str]:
    """Drop-in fix for withdrawal page missing anti-clickjacking headers."""
    response_headers["X-Frame-Options"] = "DENY"
    response_headers["Content-Security-Policy"] = "frame-ancestors 'none'"
    response_headers["X-Content-Type-Options"] = "nosniff"
    return response_headers


# ═══════════════════════════════════════════════════════════════════
# Tests
# ═══════════════════════════════════════════════════════════════════


def test_secure_headers_middleware():
    def dummy_app(environ, start_response):
        start_response("200 OK", [("Content-Type", "text/html")])
        return [b"<html><body>test</body></html>"]

    middleware = SecureHeadersMiddleware(dummy_app)
    headers_captured = []

    def capture_start_response(status, headers, exc_info=None):
        headers_captured.extend(headers)
        return lambda x: None

    list(middleware({}, capture_start_response))
    hd = dict(headers_captured)
    assert hd.get("X-Frame-Options") == "DENY"
    assert hd.get("Content-Security-Policy") == "frame-ancestors 'none'"
    assert hd.get("X-Content-Type-Options") == "nosniff"
    print("PASS: SecureHeadersMiddleware")


def test_add_anti_clickjacking_headers():
    original = [("Content-Type", "text/html")]
    updated = add_anti_clickjacking_headers(original)
    ud = dict(updated)
    assert ud["X-Frame-Options"] == "DENY"
    assert ud["Content-Security-Policy"] == "frame-ancestors 'none'"
    assert ud["Content-Type"] == "text/html"
    print("PASS: add_anti_clickjacking_headers")


def test_double_confirmation():
    dc = DoubleConfirmation(secret_key="test-secret-key")
    challenge = dc.request_confirmation("withdraw", "user123", 100.0)
    assert challenge["type"] == "double_confirmation"
    assert "withdraw" in challenge["message"].lower()
    assert challenge["expires_in"] == 300
    token = challenge["confirm_token"]

    success, msg = dc.confirm(token)
    assert success, f"Expected success, got: {msg}"
    assert "confirmed" in msg.lower()

    # Cannot reuse
    success, msg = dc.confirm(token)
    assert not success
    print("PASS: DoubleConfirmation")


def test_fix_withdrawal_page_security():
    original = {"Content-Type": "text/html"}
    fixed = fix_withdrawal_page_security(original)
    assert fixed["X-Frame-Options"] == "DENY"
    assert fixed["Content-Security-Policy"] == "frame-ancestors 'none'"
    assert fixed["Content-Type"] == "text/html"
    print("PASS: fix_withdrawal_page_security")


def test_set_anti_clickjacking_headers():
    class MockResponse:
        def __init__(self):
            self.headers = {}

    resp = MockResponse()
    set_anti_clickjacking_headers(resp)
    assert resp.headers["X-Frame-Options"] == "DENY"
    assert resp.headers["Content-Security-Policy"] == "frame-ancestors 'none'"
    print("PASS: set_anti_clickjacking_headers")


def test_critical_actions():
    for a in ("withdraw", "transfer", "send", "approve", "delegate"):
        assert a in CRITICAL_ACTIONS
    print("PASS: Critical actions")


def test_expired_token():
    dc = DoubleConfirmation(secret_key="test-key")
    challenge = dc.request_confirmation("withdraw", "user1", 50.0)
    token = challenge["confirm_token"]
    # Force expiry
    dc._pending[token]["timestamp"] = int(time.time()) - 600
    success, msg = dc.confirm(token)
    assert not success
    assert "expired" in msg.lower()
    print("PASS: Expired token rejection")


def test_cleanup_expired():
    dc = DoubleConfirmation(secret_key="test-key")
    challenge = dc.request_confirmation("withdraw", "user1", 50.0)
    token = challenge["confirm_token"]
    dc._pending[token]["timestamp"] = int(time.time()) - 600
    dc.cleanup_expired()
    assert token not in dc._pending
    print("PASS: Cleanup expired")


if __name__ == "__main__":
    test_secure_headers_middleware()
    test_add_anti_clickjacking_headers()
    test_double_confirmation()
    test_fix_withdrawal_page_security()
    test_set_anti_clickjacking_headers()
    test_critical_actions()
    test_expired_token()
    test_cleanup_expired()
    print("\n✅ ALL 8 TESTS PASSED — Clickjacking Protection Fix Complete!")
