"""Tests for issue #344 WebSocket origin and session hardening."""

from __future__ import annotations

import unittest

from fixes.websocket_origin_session_fix import (
    WebSocketHandshakeGuard,
    WebSocketSecurityError,
    generate_ws_session_id,
    websocket_cookie_headers,
)


class WebSocketOriginSessionFixTests(unittest.TestCase):
    def test_accepts_allowed_origin_with_csrf_and_authenticated_user(self) -> None:
        guard = WebSocketHandshakeGuard(frozenset({"https://app.example.com"}))

        accepted = guard.validate(
            {
                "Origin": "https://APP.example.com",
                "Sec-WebSocket-Protocol": "csrf-token",
            },
            {"csrf_token": "csrf-token", "user_id": "user-123"},
            session_id_factory=lambda: "fresh-ws-session",
        )

        self.assertEqual(accepted.origin, "https://app.example.com")
        self.assertEqual(accepted.user_id, "user-123")
        self.assertEqual(accepted.session_id, "fresh-ws-session")

    def test_rejects_missing_origin(self) -> None:
        guard = WebSocketHandshakeGuard(frozenset({"https://app.example.com"}))

        with self.assertRaises(WebSocketSecurityError):
            guard.validate(
                {"Sec-WebSocket-Protocol": "csrf-token"},
                {"csrf_token": "csrf-token", "user_id": "user-123"},
            )

    def test_rejects_cross_site_origin(self) -> None:
        guard = WebSocketHandshakeGuard(frozenset({"https://app.example.com"}))

        with self.assertRaises(WebSocketSecurityError):
            guard.validate(
                {"Origin": "https://evil.example", "Sec-WebSocket-Protocol": "csrf-token"},
                {"csrf_token": "csrf-token", "user_id": "user-123"},
            )

    def test_rejects_plain_http_origin(self) -> None:
        guard = WebSocketHandshakeGuard(frozenset({"https://app.example.com"}))

        with self.assertRaises(WebSocketSecurityError):
            guard.validate_origin("http://app.example.com")

    def test_rejects_missing_or_mismatched_csrf(self) -> None:
        guard = WebSocketHandshakeGuard(frozenset({"https://app.example.com"}))

        with self.assertRaises(WebSocketSecurityError):
            guard.validate(
                {"Origin": "https://app.example.com"},
                {"csrf_token": "csrf-token", "user_id": "user-123"},
            )

        with self.assertRaises(WebSocketSecurityError):
            guard.validate(
                {"Origin": "https://app.example.com", "Sec-WebSocket-Protocol": "wrong"},
                {"csrf_token": "csrf-token", "user_id": "user-123"},
            )

    def test_rejects_missing_user(self) -> None:
        guard = WebSocketHandshakeGuard(frozenset({"https://app.example.com"}))

        with self.assertRaises(WebSocketSecurityError):
            guard.validate(
                {"Origin": "https://app.example.com", "Sec-WebSocket-Protocol": "csrf-token"},
                {"csrf_token": "csrf-token"},
            )

    def test_generated_session_ids_are_unique_and_high_entropy(self) -> None:
        tokens = {generate_ws_session_id() for _ in range(200)}

        self.assertEqual(len(tokens), 200)
        self.assertTrue(all(len(token) >= 32 for token in tokens))

    def test_cookie_headers_use_strict_browser_defaults(self) -> None:
        headers = websocket_cookie_headers("fresh-ws-session")
        cookie = headers["Set-Cookie"]

        self.assertIn("ws_session=fresh-ws-session", cookie)
        self.assertIn("HttpOnly", cookie)
        self.assertIn("SameSite=Strict", cookie)
        self.assertIn("Secure", cookie)

    def test_cookie_headers_reject_empty_session_id(self) -> None:
        with self.assertRaises(WebSocketSecurityError):
            websocket_cookie_headers("")


if __name__ == "__main__":
    unittest.main()
