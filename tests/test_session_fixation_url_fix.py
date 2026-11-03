"""Tests for Issue #1491 Session Fixation and URL Session ID Fix."""

from __future__ import annotations

import unittest

from fixes.session_fixation_url_fix import SessionManager


class SessionFixationUrlFixTests(unittest.TestCase):
    def test_url_session_id_rejected(self) -> None:
        mgr = SessionManager()
        sid = mgr.create_session("alice")

        # Passing session ID via query params should be rejected
        result = mgr.validate_session(sid, query_params={"sid": sid})
        self.assertIsNone(result)

        result2 = mgr.validate_session(sid, query_params={"session_id": sid})
        self.assertIsNone(result2)

        # Without query params, valid session works
        self.assertEqual(mgr.validate_session(sid), "alice")

    def test_session_regeneration_on_login(self) -> None:
        mgr = SessionManager()
        pre_login_sid = mgr.create_session(None)

        # Login regenerates session ID and binds to user
        post_login_sid = mgr.login(pre_login_sid, user_id="bob")

        self.assertNotEqual(pre_login_sid, post_login_sid)
        self.assertIsNone(mgr.validate_session(pre_login_sid))
        self.assertEqual(mgr.validate_session(post_login_sid), "bob")

    def test_secure_cookie_attributes(self) -> None:
        mgr = SessionManager()
        attrs = mgr.get_cookie_attrs()
        self.assertTrue(attrs["httponly"])
        self.assertTrue(attrs["secure"])
        self.assertEqual(attrs["samesite"], "Strict")


if __name__ == "__main__":
    unittest.main()
