from __future__ import annotations

import unittest

from fixes.mass_assignment_microservice_chain_fix import (
    Account,
    MassAssignmentViolation,
    apply_public_profile_update,
    build_auth_profile_event,
    sanitize_public_profile_update,
    vulnerable_bind,
)


class MassAssignmentMicroserviceChainFixTests(unittest.TestCase):
    def setUp(self) -> None:
        self.account = Account(
            user_id="u-123",
            email="user@example.com",
            tenant_id="tenant-a",
            role="member",
            is_admin=False,
            display_name="Original",
        )

    def test_public_profile_fields_are_applied(self) -> None:
        updated = apply_public_profile_update(
            self.account,
            {"display_name": "Ada", "bio": "Builder", "timezone": "America/Chicago", "marketing_opt_in": True},
        )

        self.assertEqual(updated.display_name, "Ada")
        self.assertEqual(updated.bio, "Builder")
        self.assertEqual(updated.timezone, "America/Chicago")
        self.assertTrue(updated.marketing_opt_in)
        self.assertEqual(updated.role, "member")
        self.assertFalse(updated.is_admin)

    def test_privilege_fields_are_rejected(self) -> None:
        payload = {"display_name": "Eve", "role": "owner", "is_admin": True, "tenant_id": "tenant-b"}

        with self.assertRaises(MassAssignmentViolation) as ctx:
            sanitize_public_profile_update(payload)

        self.assertEqual(set(ctx.exception.fields), {"role", "is_admin", "tenant_id"})

    def test_case_and_dash_variants_of_server_fields_are_rejected(self) -> None:
        for key in ("ROLE", "is-admin", "Tenant_ID", "permissions"):
            with self.subTest(key=key):
                with self.assertRaises(MassAssignmentViolation):
                    sanitize_public_profile_update({key: "attacker"})

    def test_unknown_and_suspicious_keys_are_rejected(self) -> None:
        for key in ("profile.role", "profile[role]", "$set", "__proto__", "constructor.prototype.role", "nickname"):
            with self.subTest(key=key):
                with self.assertRaises(MassAssignmentViolation):
                    sanitize_public_profile_update({key: "admin"})

    def test_nested_values_cannot_be_smuggled_into_scalar_profile_fields(self) -> None:
        with self.assertRaises(MassAssignmentViolation):
            sanitize_public_profile_update({"display_name": {"$ne": ""}})

    def test_wrong_types_are_rejected(self) -> None:
        with self.assertRaises(MassAssignmentViolation):
            sanitize_public_profile_update({"marketing_opt_in": "true"})

    def test_downstream_auth_event_uses_trusted_account_state_only(self) -> None:
        updated = apply_public_profile_update(self.account, {"display_name": "Safe Name"})
        event = build_auth_profile_event(updated)

        self.assertEqual(event["role"], "member")
        self.assertFalse(event["is_admin"])
        self.assertEqual(event["tenant_id"], "tenant-a")
        self.assertEqual(event["profile"]["display_name"], "Safe Name")

    def test_vulnerable_bind_demonstrates_privilege_escalation_vector(self) -> None:
        compromised = vulnerable_bind(self.account, {"role": "owner", "is_admin": True})

        self.assertEqual(compromised.role, "owner")
        self.assertTrue(compromised.is_admin)

        with self.assertRaises(MassAssignmentViolation):
            apply_public_profile_update(self.account, {"role": "owner", "is_admin": True})


if __name__ == "__main__":
    unittest.main()
