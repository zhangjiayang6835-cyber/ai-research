from __future__ import annotations

import unittest

from fixes.ldap_auth_injection_fix import (
    LDAPAccount,
    LDAPAuthError,
    authenticate_user,
    build_user_lookup_filter,
    escape_ldap_filter_value,
)


class LDAPAuthInjectionTests(unittest.TestCase):
    def test_filter_values_escape_ldap_metacharacters(self) -> None:
        self.assertEqual(escape_ldap_filter_value(r"*)(uid=*))(\x00"), r"\2a\29\28uid=\2a\29\29\28\5cx00")

    def test_lookup_filter_contains_only_escaped_safe_username(self) -> None:
        ldap_filter = build_user_lookup_filter("ada.lovelace@example.com")

        self.assertEqual(
            ldap_filter,
            "(&(uid=ada.lovelace@example.com)(objectClass=person)(accountStatus=active))",
        )

    def test_injection_shaped_username_is_rejected_before_search(self) -> None:
        searched: list[str] = []

        def search_accounts(ldap_filter: str) -> list[LDAPAccount]:
            searched.append(ldap_filter)
            return []

        with self.assertRaisesRegex(LDAPAuthError, "username"):
            authenticate_user("*)(uid=*))(|(uid=*", "secret", search_accounts, lambda _dn, _pw: True)

        self.assertEqual(searched, [])

    def test_password_is_not_embedded_in_ldap_filter(self) -> None:
        seen_filters: list[str] = []

        def search_accounts(ldap_filter: str) -> list[LDAPAccount]:
            seen_filters.append(ldap_filter)
            return [LDAPAccount("uid=ada,ou=people,dc=example,dc=com", {"accountStatus": "active"})]

        account = authenticate_user("ada", "p@ss*)(uid=*))", search_accounts, lambda dn, pw: dn.startswith("uid=ada") and pw)

        self.assertEqual(account.dn, "uid=ada,ou=people,dc=example,dc=com")
        self.assertNotIn("p@ss", seen_filters[0])

    def test_authentication_requires_exactly_one_result(self) -> None:
        for results in (
            [],
            [
                LDAPAccount("uid=a,ou=people,dc=example,dc=com", {"accountStatus": "active"}),
                LDAPAccount("uid=b,ou=people,dc=example,dc=com", {"accountStatus": "active"}),
            ],
        ):
            with self.subTest(count=len(results)):
                with self.assertRaisesRegex(LDAPAuthError, "exactly one"):
                    authenticate_user("ada", "secret", lambda _filter: results, lambda _dn, _pw: True)

    def test_disabled_account_is_rejected(self) -> None:
        account = LDAPAccount("uid=ada,ou=people,dc=example,dc=com", {"accountStatus": "disabled"})

        with self.assertRaisesRegex(LDAPAuthError, "active"):
            authenticate_user("ada", "secret", lambda _filter: [account], lambda _dn, _pw: True)

    def test_password_verifier_failure_is_rejected(self) -> None:
        account = LDAPAccount("uid=ada,ou=people,dc=example,dc=com", {"accountStatus": "active"})

        with self.assertRaisesRegex(LDAPAuthError, "invalid credentials"):
            authenticate_user("ada", "wrong", lambda _filter: [account], lambda _dn, _pw: False)

    def test_safe_schema_attribute_is_required(self) -> None:
        for attr in ("uid)(|(uid", "1uid", "uid*", "distinguishedName.long"):
            with self.subTest(attr=attr):
                with self.assertRaisesRegex(LDAPAuthError, "attribute"):
                    build_user_lookup_filter("ada", uid_attribute=attr)


if __name__ == "__main__":
    unittest.main()
