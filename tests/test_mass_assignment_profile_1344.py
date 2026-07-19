"""Tests for Mass Assignment in User Profile Update → Privilege Escalation fix (#1344)."""

from __future__ import annotations

import unittest

from fixes.mass_assignment_profile_1344_fix import (
    ALLOWED_PROFILE_FIELDS,
    FieldValidationError,
    MassAssignmentViolation,
    UserProfile,
    apply_profile_update,
    sanitize_profile_update,
)


class MassAssignmentProfile1344Tests(unittest.TestCase):
    """Test suite for issue #1344 fix."""

    def setUp(self):
        self.user = UserProfile(
            user_id="u-123",
            display_name="Original",
            bio="Hello",
            timezone="UTC",
            role="member",
            is_admin=False,
            tenant_id="tenant-a",
        )

    # ── Sanitize Profile Update ─────────────────────────────────────

    def test_allowed_fields_pass_sanitization(self) -> None:
        """Allowed fields pass through sanitization."""
        payload = {
            "display_name": "New Name",
            "bio": "Updated bio",
            "timezone": "America/Chicago",
            "marketing_opt_in": True,
        }
        sanitized = sanitize_profile_update(payload)
        self.assertEqual(sanitized["display_name"], "New Name")
        self.assertEqual(sanitized["bio"], "Updated bio")
        self.assertEqual(sanitized["timezone"], "America/Chicago")
        self.assertTrue(sanitized["marketing_opt_in"])

    def test_role_field_is_rejected(self) -> None:
        """'role' field triggers MassAssignmentViolation."""
        with self.assertRaises(MassAssignmentViolation) as ctx:
            sanitize_profile_update({
                "display_name": "Eve",
                "role": "admin",
            })
        self.assertIn("role", ctx.exception.fields)

    def test_is_admin_field_is_rejected(self) -> None:
        with self.assertRaises(MassAssignmentViolation):
            sanitize_profile_update({
                "display_name": "Eve",
                "is_admin": True,
            })

    def test_permissions_field_is_rejected(self) -> None:
        with self.assertRaises(MassAssignmentViolation):
            sanitize_profile_update({
                "display_name": "Eve",
                "permissions": ["read", "write", "admin"],
            })

    def test_tenant_id_field_is_rejected(self) -> None:
        with self.assertRaises(MassAssignmentViolation):
            sanitize_profile_update({
                "display_name": "Eve",
                "tenant_id": "tenant-b",
            })

    def test_case_variant_fields_are_rejected(self) -> None:
        """Case variations of privileged fields are detected."""
        for key in ("ROLE", "Is_Admin", "IS_ADMIN", "Permissions"):
            with self.subTest(key=key):
                with self.assertRaises(MassAssignmentViolation):
                    sanitize_profile_update({
                        "display_name": "Eve",
                        key: "admin",
                    })

    def test_hyphen_variant_fields_are_rejected(self) -> None:
        """Hyphen-separated variants are detected."""
        with self.assertRaises(MassAssignmentViolation):
            sanitize_profile_update({
                "display_name": "Eve",
                "is-admin": True,
            })

    def test_unknown_fields_are_silently_removed(self) -> None:
        """Unknown fields are stripped without error."""
        sanitized = sanitize_profile_update({
            "display_name": "Test",
            "some_random_field": "value",
        })
        self.assertIn("display_name", sanitized)
        self.assertNotIn("some_random_field", sanitized)

    def test_empty_payload_returns_empty_dict(self) -> None:
        sanitized = sanitize_profile_update({})
        self.assertEqual(sanitized, {})

    def test_invalid_display_name_type_is_rejected(self) -> None:
        with self.assertRaises(FieldValidationError):
            sanitize_profile_update({"display_name": 123})

    def test_invalid_marketing_opt_in_type_is_rejected(self) -> None:
        with self.assertRaises(FieldValidationError):
            sanitize_profile_update({"marketing_opt_in": "yes"})

    # ── Apply Profile Update ────────────────────────────────────────

    def test_apply_update_with_allowed_fields(self) -> None:
        updated = apply_profile_update(
            {
                "user_id": "u-123",
                "display_name": "Old",
                "role": "member",
                "is_admin": False,
            },
            {"display_name": "New"},
        )
        self.assertEqual(updated["display_name"], "New")
        self.assertEqual(updated["role"], "member")  # Not changed

    def test_apply_update_rejects_privileged_fields(self) -> None:
        with self.assertRaises(MassAssignmentViolation):
            apply_profile_update(
                {"user_id": "u-123", "display_name": "Old"},
                {"display_name": "Eve", "role": "admin"},
            )

    # ── UserProfile.update() Integration ────────────────────────────

    def test_user_profile_update_allowed_fields(self) -> None:
        self.user.update({
            "display_name": "Alice",
            "bio": "Security researcher",
        })
        self.assertEqual(self.user.display_name, "Alice")
        self.assertEqual(self.user.bio, "Security researcher")
        self.assertEqual(self.user.role, "member")  # Unchanged
        self.assertFalse(self.user.is_admin)  # Unchanged

    def test_user_profile_update_rejects_privileged_fields(self) -> None:
        with self.assertRaises(MassAssignmentViolation):
            self.user.update({
                "display_name": "Eve",
                "role": "owner",
                "is_admin": True,
            })
        # Verify no changes were applied
        self.assertEqual(self.user.display_name, "Original")
        self.assertEqual(self.user.role, "member")

    def test_user_profile_update_strips_unknown_fields(self) -> None:
        self.user.update({
            "display_name": "Bob",
            "extra_field": "should be ignored",
        })
        self.assertEqual(self.user.display_name, "Bob")
        self.assertFalse(hasattr(self.user, "extra_field"))


if __name__ == "__main__":
    unittest.main()
