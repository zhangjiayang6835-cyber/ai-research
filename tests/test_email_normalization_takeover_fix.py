from __future__ import annotations

import unittest

from fixes.email_normalization_takeover_fix import (
    DuplicateEmail,
    EmailIdentityStore,
    InvalidEmail,
    canonical_email,
    normalize_email_syntax,
)


class EmailNormalizationTakeoverTests(unittest.TestCase):
    def test_gmail_alias_registration_collides_with_existing_account(self) -> None:
        store = EmailIdentityStore()
        victim = store.register("victim", "Victim.Name@gmail.com")

        self.assertEqual(victim.canonical_email, "victimname@gmail.com")
        with self.assertRaises(DuplicateEmail):
            store.register("attacker", "victimname+reset@googlemail.com")

    def test_password_reset_delivers_only_to_verified_account_email(self) -> None:
        store = EmailIdentityStore()
        store.register("victim", "Victim.Name@gmail.com")

        dispatch = store.issue_password_reset(
            "victimname+attacker-controlled-label@googlemail.com",
            lambda account: f"reset-for-{account.user_id}",
        )

        self.assertIsNotNone(dispatch)
        assert dispatch is not None
        self.assertEqual(dispatch.user_id, "victim")
        self.assertEqual(dispatch.deliver_to, "victim.name@gmail.com")
        self.assertEqual(dispatch.token, "reset-for-victim")

    def test_lookup_uses_same_canonical_key_as_registration(self) -> None:
        store = EmailIdentityStore()
        store.register("user-1", "Alice@Example.COM")

        self.assertEqual(store.find_by_email("alice@example.com").user_id, "user-1")
        self.assertEqual(store.find_by_email("ALICE@EXAMPLE.com").user_id, "user-1")

    def test_non_gmail_plus_address_is_not_over_normalized(self) -> None:
        store = EmailIdentityStore()
        first = store.register("base", "user@example.com")
        second = store.register("tagged", "user+billing@example.com")

        self.assertEqual(first.canonical_email, "user@example.com")
        self.assertEqual(second.canonical_email, "user+billing@example.com")
        self.assertEqual(store.find_by_email("user+billing@example.com").user_id, "tagged")

    def test_unknown_reset_request_has_no_dispatch_target(self) -> None:
        store = EmailIdentityStore()
        store.register("victim", "victim@example.com")

        self.assertIsNone(store.issue_password_reset("nobody@example.com", lambda account: "token"))

    def test_invalid_inputs_are_rejected_before_indexing(self) -> None:
        for value in (
            "",
            "missing-at.example.com",
            "too@many@example.com",
            "local-only@",
            "@domain-only.example",
            "user@example",
            "user name@example.com",
            "user@example.com\nbcc:attacker@example.com",
        ):
            with self.subTest(value=value):
                with self.assertRaises(InvalidEmail):
                    canonical_email(value)

    def test_normalized_storage_keeps_provider_alias_as_display_address(self) -> None:
        self.assertEqual(
            normalize_email_syntax(" Victim.Name+news@GoogleMail.COM "),
            "victim.name+news@googlemail.com",
        )
        self.assertEqual(
            canonical_email(" Victim.Name+news@GoogleMail.COM "),
            "victimname@gmail.com",
        )


if __name__ == "__main__":
    unittest.main()
