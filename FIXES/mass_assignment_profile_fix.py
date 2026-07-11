"""
Fix for Issue #964 — Mass Assignment in User Profile Update → Privilege Escalation

Vulnerability
-------------
The user profile update endpoint directly binds all request parameters to the
user model (e.g. `User.update(params)`).  An attacker can inject privileged
fields such as `role=admin` or `is_admin=true` and escalate to admin.

Fix
---
Implement a **strict whitelist / DTO pattern** so only explicitly allowed
fields can be updated.  All privileged fields are filtered out server-side.

Usage
-----
    from FIXES.mass_assignment_profile_fix import SecureProfileUpdate

    @app.route('/profile', methods=['PUT'])
    def update_profile():
        updater = SecureProfileUpdate()
        safe_data, rejected = updater.sanitize(request.form.to_dict())
        db.users.update_one({'_id': session['user_id']}, {'$set': safe_data})
        return jsonify({'updated': safe_data, 'rejected': rejected})

Self-tests
----------
    python FIXES/mass_assignment_profile_fix.py
"""

from __future__ import annotations

import copy
import json
from typing import Any, Dict, List, Set, Tuple


# ---------------------------------------------------------------------------
# Configuration — only these fields may be updated by the user
# ---------------------------------------------------------------------------
ALLOWED_FIELDS: Set[str] = {
    "display_name",
    "bio",
    "avatar_url",
    "timezone",
    "language",
    "email",
    "phone",
    "notifications_enabled",
}

# ---------------------------------------------------------------------------
# Privileged fields that MUST never be mass-assigned
# ---------------------------------------------------------------------------
SENSITIVE_FIELDS: Set[str] = {
    # Role / permission escalation
    "role",
    "roles",
    "is_admin",
    "is_superuser",
    "is_staff",
    "permissions",
    "permission",
    "admin",
    "sudo",
    # Ownership / identity
    "owner",
    "owner_id",
    "created_by",
    "assigned_to",
    # Security
    "password",
    "password_hash",
    "password_reset_token",
    "session_token",
    "api_key",
    "api_keys",
    "secret",
    "token",
    "totp_secret",
    "mfa_enabled",
    "mfa_secret",
    # Billing / financial
    "balance",
    "credit",
    "credits",
    "subscription",
    "plan",
    "billing",
    "invoice",
    # Metadata
    "id",
    "_id",
    "user_id",
    "created_at",
    "updated_at",
    "deleted_at",
    "status",
}

# Fields we simply refuse to touch regardless of whitelist (hard blacklist)
HARD_BLACKLIST: Set[str] = {
    "__class__",
    "__dict__",
    "__module__",
    "__init__",
    "__globals__",
    "__builtins__",
    "class",
    "constructor",
}


class ProfileUpdateDTO:
    """Data Transfer Object for safe profile updates.

    Only fields in ALLOWED_FIELDS are accepted; every other field is
    recorded as rejected and never written to the database.
    """

    def __init__(self, raw: Dict[str, Any]):
        self.raw = copy.deepcopy(raw)
        self.allowed: Dict[str, Any] = {}
        self.rejected: List[str] = []
        self._sanitize()

    def _sanitize(self) -> None:
        for key, value in self.raw.items():
            key_lower = key.lower().strip()
            if key_lower in HARD_BLACKLIST:
                self.rejected.append(f"{key} (hard-blocked)")
                continue
            if key_lower in SENSITIVE_FIELDS:
                self.rejected.append(f"{key} (sensitive)")
                continue
            if key_lower in ALLOWED_FIELDS:
                # Normalise booleans / ints from string POST data
                self.allowed[key_lower] = self._coerce(value)
            else:
                self.rejected.append(f"{key} (not in whitelist)")

    @staticmethod
    def _coerce(value: Any) -> Any:
        if isinstance(value, str) and value.lower() in ("true", "false"):
            return value.lower() == "true"
        if isinstance(value, str) and value.isdigit():
            return int(value)
        return value

    def is_safe(self) -> bool:
        return bool(self.allowed)

    def to_dict(self) -> Dict[str, Any]:
        return dict(self.allowed)


# ---------------------------------------------------------------------------
# Convenience class for use inside Flask route handlers
# ---------------------------------------------------------------------------
class SecureProfileUpdate:
    """Singleton-style helper for profile update routes."""

    def sanitize(
        self,
        raw: Dict[str, Any],
        allowed: Set[str] | None = None,
    ) -> Tuple[Dict[str, Any], List[str]]:
        dto = ProfileUpdateDTO(raw)
        if allowed is not None:
            # Additional caller-supplied whitelist — intersects with ALLOWED_FIELDS
            effective = allowed & ALLOWED_FIELDS
            dto.allowed = {k: v for k, v in dto.allowed.items() if k in effective}
        return dto.to_dict(), dto.rejected


# ---------------------------------------------------------------------------
# Flask example — drop-in route
# ---------------------------------------------------------------------------
def install_secure_profile_route(app) -> None:
    """Install a /profile PUT route that uses the whitelist pattern.

    Call from your app factory:
        install_secure_profile_route(app)
    """
    updater = SecureProfileUpdate()

    @app.route("/profile", methods=["PUT"])
    def update_profile():
        from flask import jsonify, session

        if "user_id" not in session:
            return jsonify({"error": "Not authenticated"}), 401

        raw = request.form.to_dict() if hasattr(request, "form") else {}
        if not raw and hasattr(request, "get_json"):
            raw = request.get_json(silent=True) or {}

        safe_data, rejected = updater.sanitize(raw)

        if not safe_data:
            return jsonify({
                "error": "No valid fields to update",
                "rejected": rejected,
            }), 400

        # Write only the safe, whitelisted fields to DB
        # (actual DB driver omitted — adapt to your ORM)
        return jsonify({
            "updated": safe_data,
            "rejected": rejected,
            "message": "Profile updated with whitelist validation",
        })


# ---------------------------------------------------------------------------
# Self-tests
# ---------------------------------------------------------------------------
def _test() -> None:
    passed = 0
    failed = 0

    def check(name: str, condition: bool) -> None:
        nonlocal passed, failed
        if condition:
            passed += 1
        else:
            failed += 1
            print(f"  FAIL: {name}")

    print("=== Mass Assignment Fix — Self-tests ===")

    # 1. Whitelisted fields pass through
    dto = ProfileUpdateDTO({"display_name": "Alice", "bio": "hello"})
    check("whitelist accept", dto.allowed == {"display_name": "Alice", "bio": "hello"})

    # 2. role= is blocked
    dto = ProfileUpdateDTO({"display_name": "Bob", "role": "admin"})
    check("role blocked", "role" not in dto.allowed)
    check("role in rejected", any("role" in r.lower() for r in dto.rejected))

    # 3. is_admin= is blocked
    dto = ProfileUpdateDTO({"is_admin": True, "email": "a@b.com"})
    check("is_admin blocked", "is_admin" not in dto.allowed)
    check("email still accepted", "email" in dto.allowed)

    # 4. __class__ / dunder keys blocked
    dto = ProfileUpdateDTO({"__class__": "pwn", "display_name": "X"})
    check("__class__ blocked", "__class__" not in dto.allowed)
    check("display_name still accepted", "display_name" in dto.allowed)

    # 5. balance manipulation blocked
    dto = ProfileUpdateDTO({"balance": 99999, "credits": "max"})
    check("balance blocked", "balance" not in dto.allowed)
    check("credits blocked", "credits" not in dto.allowed)

    # 6. Empty payload
    dto = ProfileUpdateDTO({})
    check("empty is not safe", not dto.is_safe())

    # 7. SecureProfileUpdate.sanitize interface
    updater = SecureProfileUpdate()
    safe, rejected = updater.sanitize({"bio": "test", "role": "admin", "xyz": "abc"})
    check("sanitize safe keys", safe == {"bio": "test"})
    check("sanitize rejects 2", len(rejected) == 2)

    # 8. Boolean coercion
    dto = ProfileUpdateDTO({"notifications_enabled": "true"})
    check("bool coercion", dto.allowed["notifications_enabled"] is True)

    # 9. Int coercion
    dto = ProfileUpdateDTO({"timezone": "5"})
    check("int coercion", dto.allowed["timezone"] == 5)

    # 10. Case-insensitive sensitivity
    dto = ProfileUpdateDTO({"Role": "admin", "IS_ADMIN": True})
    check("case-insensitive role", "role" not in dto.allowed)
    check("case-insensitive is_admin", "is_admin" not in dto.allowed)

    print(f"\nResults: {passed} passed, {failed} failed")
    if failed:
        raise AssertionError(f"{failed} test(s) failed")
    print("All self-tests PASSED ✅")


if __name__ == "__main__":
    _test()
