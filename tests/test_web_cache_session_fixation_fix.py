"""Tests for issue #339 cache deception and session fixation hardening."""

from __future__ import annotations

import unittest

from fixes.web_cache_session_fixation_fix import (
    SessionFixationGuard,
    WebCacheDeceptionGuard,
    WebCacheSessionFixationError,
    secure_session_cookie_headers,
)


class WebCacheSessionFixationFixTests(unittest.TestCase):
    def test_rejects_private_route_with_static_suffix(self) -> None:
        guard = WebCacheDeceptionGuard()

        with self.assertRaises(WebCacheSessionFixationError):
            guard.validate_route("/account/profile.css", authenticated=True)

    def test_rejects_encoded_static_suffix_on_private_route(self) -> None:
        guard = WebCacheDeceptionGuard()

        with self.assertRaises(WebCacheSessionFixationError):
            guard.validate_route("/settings/security%2Ejpg", authenticated=True)

    def test_private_response_gets_no_store_and_vary_headers(self) -> None:
        decision = WebCacheDeceptionGuard().cache_decision(
            "/dashboard",
            authenticated=True,
            contains_private_data=True,
        )

        self.assertFalse(decision.cacheable)
        self.assertEqual(decision.headers["Cache-Control"], "no-store, private")
        self.assertEqual(decision.headers["Vary"], "Authorization, Cookie")

    def test_public_static_asset_can_be_cached(self) -> None:
        decision = WebCacheDeceptionGuard().cache_decision(
            "/assets/app.css",
            authenticated=False,
            contains_private_data=False,
        )

        self.assertTrue(decision.cacheable)
        self.assertIn("immutable", decision.headers["Cache-Control"])

    def test_public_dynamic_response_is_not_cached_by_default(self) -> None:
        decision = WebCacheDeceptionGuard().cache_decision(
            "/articles/latest",
            authenticated=False,
            contains_private_data=False,
        )

        self.assertFalse(decision.cacheable)
        self.assertEqual(decision.headers["Cache-Control"], "no-store")

    def test_session_rotation_clears_attacker_controlled_state(self) -> None:
        session = {
            "session_id": "attacker-fixed-id",
            "csrf_token": "existing-csrf-token",
            "next": "https://evil.example",
            "authenticated": False,
        }
        guard = SessionFixationGuard(token_factory=lambda: "fresh-session-id")

        new_id = guard.rotate_on_authentication(session, user_id="user-123")

        self.assertEqual(new_id, "fresh-session-id")
        self.assertEqual(
            session,
            {
                "authenticated": True,
                "csrf_token": "existing-csrf-token",
                "session_id": "fresh-session-id",
                "session_rotated": True,
                "user_id": "user-123",
            },
        )

    def test_session_cookie_header_uses_safe_defaults(self) -> None:
        headers = secure_session_cookie_headers("fresh-session-id")
        cookie = headers["Set-Cookie"]

        self.assertIn("session_id=fresh-session-id", cookie)
        self.assertIn("HttpOnly", cookie)
        self.assertIn("SameSite=Lax", cookie)
        self.assertIn("Secure", cookie)

    def test_session_cookie_rejects_missing_id(self) -> None:
        with self.assertRaises(WebCacheSessionFixationError):
            secure_session_cookie_headers("")


if __name__ == "__main__":
    unittest.main()
