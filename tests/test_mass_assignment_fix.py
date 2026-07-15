"""Tests for mass-assignment → privilege-escalation fix (Issue #1183).

Covers:
  - Field whitelisting (per-role policies)
  - Rejection of privileged fields by non-admin callers
  - Immutable field rejection (even for admins)
  - Case-variation attacks (IsAdmin, ROLE, etc.)
  - NoSQL operator / prototype pollution key smuggling
  - Unknown field rejection (strict mode)
  - Type validation (non-scalar rejection)
  - Oversized string DoS guard
  - Route-level integration (profile update + admin update)
"""
from __future__ import annotations

import unittest
from typing import Any, Mapping

from src.models.user import (
    IMMUTABLE_FIELDS,
    PRIVILEGED_FIELDS,
    USER_ADMIN_POLICY,
    USER_SELF_POLICY,
    FieldPolicy,
    MassAssignmentError,
    User,
    sanitize_payload,
)
from src.routes.user_routes import admin_update_user, update_profile


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

class FakeUser:
    """Minimal User stand-in for route-level tests."""

    def __init__(self, **kwargs: Any) -> None:
        self.id: str = kwargs.pop("id", "u-001")
        self.role: str = kwargs.pop("role", "user")
        self.is_admin: bool = kwargs.pop("is_admin", False)
        self.name: str = kwargs.pop("name", "alice")
        self.password_hash: str = kwargs.pop("password_hash", "hash")
        for k, v in kwargs.items():
            setattr(self, k, v)

    def save(self) -> None:
        pass


class FakeRequest:
    """Stub request with controllable JSON body."""

    def __init__(self, body: dict) -> None:
        self._body = body

    def get_json(self) -> dict:
        return self._body


# ---------------------------------------------------------------------------
# 1. sanitize_payload — unit tests
# ---------------------------------------------------------------------------

class TestSanitizePayload(unittest.TestCase):
    """Core sanitizer logic."""

    def test_returns_empty_dict_for_none(self) -> None:
        self.assertEqual(sanitize_payload(None, USER_SELF_POLICY), {})

    def test_rejects_non_mapping(self) -> None:
        with self.assertRaises(MassAssignmentError):
            sanitize_payload([("x", 1)], USER_SELF_POLICY)  # type: ignore[arg-type]

    def test_returns_only_allowed_fields(self) -> None:
        payload = {"name": "Bob", "bio": "Hi", "unknown": 1}
        # strict=False so unknown fields are dropped
        policy = FieldPolicy("User", "user", USER_SELF_POLICY.allowed, strict=False)
        result = sanitize_payload(payload, policy, actor_id="u1")
        self.assertIn("name", result)
        self.assertIn("bio", result)
        self.assertNotIn("unknown", result)

    def test_rejects_immutable_fields(self) -> None:
        for key in IMMUTABLE_FIELDS:
            with self.subTest(key=key):
                with self.assertRaises(MassAssignmentError) as ctx:
                    sanitize_payload({key: "val"}, USER_SELF_POLICY, actor_id="u1")
                self.assertIn(key, ctx.exception.offending)

    def test_rejects_privileged_fields_from_non_admin(self) -> None:
        for key in ["role", "is_admin", "is_superuser", "permissions"]:
            with self.subTest(key=key):
                with self.assertRaises(MassAssignmentError) as ctx:
                    sanitize_payload({key: "evil"}, USER_SELF_POLICY, actor_id="u1")
                self.assertIn(key, ctx.exception.offending)

    def test_admin_policy_allows_privileged_fields(self) -> None:
        result = sanitize_payload(
            {"role": "admin", "is_admin": True},
            USER_ADMIN_POLICY,
            actor_id="root",
        )
        self.assertEqual(result["role"], "admin")
        self.assertTrue(result["is_admin"])

    def test_case_variations_rejected(self) -> None:
        for key in ["ROLE", "IsAdmin", "TENANT_ID", "PERMISSIONS"]:
            with self.subTest(key=key):
                with self.assertRaises(MassAssignmentError):
                    sanitize_payload({key: "val"}, USER_SELF_POLICY, actor_id="u1")

    def test_suspicious_keys_rejected(self) -> None:
        for key in [
            "__proto__", "constructor.prototype", "role[$ne]", "$set",
            "profile.role", "name.__proto__",
        ]:
            with self.subTest(key=key):
                with self.assertRaises(MassAssignmentError):
                    sanitize_payload({key: "val"}, USER_SELF_POLICY, actor_id="u1")

    def test_non_scalar_values_rejected(self) -> None:
        with self.assertRaises(MassAssignmentError):
            sanitize_payload({"name": {"$ne": None}}, USER_SELF_POLICY, actor_id="u1")

    def test_list_values_rejected(self) -> None:
        with self.assertRaises(MassAssignmentError):
            sanitize_payload({"bio": [1, 2, 3]}, USER_SELF_POLICY, actor_id="u1")

    def test_oversized_string_rejected(self) -> None:
        with self.assertRaises(MassAssignmentError):
            sanitize_payload({"name": "A" * 5000}, USER_SELF_POLICY, actor_id="u1")

    def test_unknown_fields_strict_mode_raises(self) -> None:
        with self.assertRaises(MassAssignmentError) as ctx:
            sanitize_payload({"random": 1}, USER_SELF_POLICY, actor_id="u1")
        self.assertIn("random", ctx.exception.offending)

    def test_unknown_fields_lenient_mode_silent_drop(self) -> None:
        policy = FieldPolicy("User", "user", USER_SELF_POLICY.allowed, strict=False)
        result = sanitize_payload({"random": 1}, policy, actor_id="u1")
        self.assertNotIn("random", result)


# ---------------------------------------------------------------------------
# 2. FieldPolicy construction
# ---------------------------------------------------------------------------

class TestFieldPolicy(unittest.TestCase):

    def test_rejects_immutable_fields_in_allowlist(self) -> None:
        with self.assertRaises(ValueError):
            FieldPolicy("User", "user", frozenset({"name", "id"}))

    def test_valid_policy(self) -> None:
        p = FieldPolicy("User", "user", frozenset({"name", "bio"}))
        self.assertEqual(p.model, "User")
        self.assertEqual(p.actor_role, "user")


# ---------------------------------------------------------------------------
# 3. User model — constructor and safe_update
# ---------------------------------------------------------------------------

class TestUserModel(unittest.TestCase):

    def test_constructor_sets_all_fields(self) -> None:
        u = User(name="alice", is_admin=True, role="superuser")
        self.assertEqual(u.name, "alice")
        self.assertTrue(u.is_admin)
        self.assertEqual(u.role, "superuser")

    def test_safe_update_rejects_privilege_escalation(self) -> None:
        u = User(name="alice")
        with self.assertRaises(MassAssignmentError):
            u.safe_update({"name": "bob", "is_admin": True})
        self.assertEqual(u.name, "alice")
        self.assertFalse(getattr(u, "is_admin", False))

    def test_safe_update_rejects_role_injection(self) -> None:
        u = User(name="alice")
        with self.assertRaises(MassAssignmentError):
            u.safe_update({"role": "superuser"})

    def test_safe_update_applies_allowed_fields(self) -> None:
        u = User(name="alice")
        u.safe_update({"name": "bob", "bio": "hello"})
        self.assertEqual(u.name, "bob")
        self.assertEqual(u.bio, "hello")

    def test_safe_update_admin_can_set_privileged_fields(self) -> None:
        u = User(name="alice")
        u.safe_update({"role": "moderator", "is_admin": True}, actor_is_admin=True)
        self.assertEqual(u.role, "moderator")
        self.assertTrue(u.is_admin)

    def test_safe_update_rejects_immutable_for_admin(self) -> None:
        u = User(name="alice")
        with self.assertRaises(MassAssignmentError):
            u.safe_update({"id": 999, "password_hash": "pwned"}, actor_is_admin=True)


# ---------------------------------------------------------------------------
# 4. Route-level integration — update_profile
# ---------------------------------------------------------------------------

class TestUpdateProfileRoute(unittest.TestCase):

    def test_valid_update(self) -> None:
        user = FakeUser(name="alice")
        req = FakeRequest({"name": "Bob", "bio": "Hi"})
        result = update_profile(req, user)
        self.assertEqual(result["status"], "ok")
        self.assertEqual(user.name, "Bob")
        self.assertEqual(user.bio, "Hi")

    def test_privilege_escalation_rejected(self) -> None:
        user = FakeUser(name="alice")
        req = FakeRequest({"name": "Bob", "is_admin": True})
        result = update_profile(req, user)
        self.assertIn("error", result)
        self.assertEqual(user.name, "alice")
        self.assertFalse(user.is_admin)

    def test_role_injection_rejected(self) -> None:
        user = FakeUser(name="alice")
        req = FakeRequest({"role": "superuser"})
        result = update_profile(req, user)
        self.assertIn("error", result)

    def test_non_dict_body_rejected(self) -> None:
        user = FakeUser()
        req = FakeRequest("not a dict")
        result = update_profile(req, user)
        self.assertIn("error", result)


# ---------------------------------------------------------------------------
# 5. Route-level integration — admin_update_user
# ---------------------------------------------------------------------------

class TestAdminUpdateUserRoute(unittest.TestCase):

    def test_admin_can_set_role(self) -> None:
        target = FakeUser(name="bob")
        admin = FakeUser(id="admin-1", is_admin=True)
        req = FakeRequest({"role": "moderator"})
        result = admin_update_user(req, target, admin)
        self.assertEqual(result["status"], "ok")
        self.assertEqual(target.role, "moderator")

    def test_admin_cannot_set_immutable(self) -> None:
        target = FakeUser(name="bob")
        admin = FakeUser(id="admin-1", is_admin=True)
        req = FakeRequest({"password_hash": "pwned"})
        result = admin_update_user(req, target, admin)
        self.assertIn("error", result)

    def test_admin_unknown_fields_rejected(self) -> None:
        target = FakeUser(name="bob")
        admin = FakeUser(id="admin-1", is_admin=True)
        req = FakeRequest({"hacked": True})
        result = admin_update_user(req, target, admin)
        self.assertIn("error", result)


# ---------------------------------------------------------------------------
# 6. End-to-end mass-assignment attack scenarios
# ---------------------------------------------------------------------------

class TestMassAssignmentAttackScenarios(unittest.TestCase):
    """Simulate real-world attacker payloads and verify they are blocked."""

    def setUp(self) -> None:
        self.user = User(name="victim")

    def test_classic_privesc(self) -> None:
        attacks = [
            {"name": "x", "is_admin": True},
            {"name": "x", "role": "superuser"},
            {"name": "x", "permissions": ["*"]},
            {"name": "x", "tenant_id": 999},
        ]
        for payload in attacks:
            with self.subTest(payload=payload):
                with self.assertRaises(MassAssignmentError):
                    self.user.safe_update(payload)
                self.assertFalse(getattr(self.user, "is_admin", False))
                self.assertNotEqual(getattr(self.user, "role", None), "superuser")

    def test_case_variant_privesc(self) -> None:
        attacks = [
            {"IsAdmin": True},
            {"ROLE": "admin"},
            {"TENANT_ID": 999},
            {"Permissions": ["all"]},
        ]
        for payload in attacks:
            with self.subTest(payload=payload):
                with self.assertRaises(MassAssignmentError):
                    self.user.safe_update(payload)

    def test_nosql_injection_via_mass_assignment(self) -> None:
        payload = {"name": {"$ne": ""}, "$where": "function(){return true}"}
        with self.assertRaises(MassAssignmentError):
            self.user.safe_update(payload)

    def test_prototype_pollution_via_mass_assignment(self) -> None:
        payload = {"__proto__": {"is_admin": True}, "constructor.prototype.role": "admin"}
        with self.assertRaises(MassAssignmentError):
            self.user.safe_update(payload)

    def test_bypass_attempt_with_hidden_fields(self) -> None:
        payload = {"name": "ok", "email_verified": True, "account_status": "active"}
        with self.assertRaises(MassAssignmentError):
            self.user.safe_update(payload)


# ---------------------------------------------------------------------------
# Run
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    unittest.main()
