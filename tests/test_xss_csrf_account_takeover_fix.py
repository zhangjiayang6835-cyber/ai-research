"""Tests for the issue #343 XSS to CSRF account takeover fix."""

from __future__ import annotations

import unittest

from fixes.xss_csrf_account_takeover_fix import (
    Account,
    AccountTakeoverGuardError,
    escape_html,
    render_profile_heading,
    rotate_session_on_login,
    secure_session_cookie_options,
    update_account_email,
    validate_csrf_token,
)


class XssCsrfAccountTakeoverFixTests(unittest.TestCase):
    def test_escape_html_encodes_script_payload(self) -> None:
        payload = '<script>alert("owned")</script>'

        escaped = escape_html(payload)

        self.assertNotIn("<script>", escaped)
        self.assertIn("&lt;script&gt;", escaped)
        self.assertIn("&quot;owned&quot;", escaped)

    def test_render_profile_heading_does_not_emit_executable_html(self) -> None:
        html = render_profile_heading("<img src=x onerror=alert(1)>")

        self.assertEqual(html, "<h1>&lt;img src=x onerror=alert(1)&gt;</h1>")

    def test_csrf_token_validation_accepts_matching_token(self) -> None:
        validate_csrf_token("known-token", "known-token")

    def test_csrf_token_validation_rejects_missing_or_mismatched_token(self) -> None:
        with self.assertRaises(AccountTakeoverGuardError):
            validate_csrf_token("known-token", None)
        with self.assertRaises(AccountTakeoverGuardError):
            validate_csrf_token("known-token", "wrong-token")

    def test_rotate_session_on_login_clears_fixation_state(self) -> None:
        session = {
            "csrf_token": "attacker-token",
            "cart_id": "prelogin-state",
            "user_id": "attacker",
        }

        rotate_session_on_login(
            session,
            user_id="victim",
            token_factory=lambda: "fresh-token",
        )

        self.assertEqual(
            session,
            {
                "authenticated": True,
                "csrf_token": "fresh-token",
                "user_id": "victim",
            },
        )

    def test_update_account_email_requires_owner_session(self) -> None:
        account = Account("victim", "old@example.com", "Victim")
        session = {"user_id": "attacker", "csrf_token": "valid-token"}

        with self.assertRaises(AccountTakeoverGuardError):
            update_account_email(
                account=account,
                session=session,
                submitted_csrf_token="valid-token",
                new_email="attacker@example.com",
            )

        self.assertEqual(account.email, "old@example.com")

    def test_update_account_email_requires_csrf_for_state_change(self) -> None:
        account = Account("victim", "old@example.com", "Victim")
        session = {"user_id": "victim", "csrf_token": "valid-token"}

        with self.assertRaises(AccountTakeoverGuardError):
            update_account_email(
                account=account,
                session=session,
                submitted_csrf_token="stolen-or-missing",
                new_email="attacker@example.com",
            )

        self.assertEqual(account.email, "old@example.com")

    def test_update_account_email_allows_owner_with_valid_csrf(self) -> None:
        account = Account("victim", "old@example.com", "Victim")
        session = {"user_id": "victim", "csrf_token": "valid-token"}

        updated = update_account_email(
            account=account,
            session=session,
            submitted_csrf_token="valid-token",
            new_email=" new@example.com ",
        )

        self.assertIs(updated, account)
        self.assertEqual(account.email, "new@example.com")

    def test_secure_cookie_options_reduce_chain_blast_radius(self) -> None:
        options = secure_session_cookie_options()

        self.assertTrue(options["httponly"])
        self.assertTrue(options["secure"])
        self.assertEqual(options["samesite"], "Strict")


if __name__ == "__main__":
    unittest.main()
