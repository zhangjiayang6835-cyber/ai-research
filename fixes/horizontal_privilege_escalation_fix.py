"""
Fix: Broken Access Control — Horizontal Privilege Escalation
=============================================================
Issue #80 — A user can access or modify another user's resources by
manipulating resource IDs (e.g., ``/api/users/123/profile`` → ``/api/users/456/profile``).

This fix provides:
1. Ownership-based access control
2. Resource-level authorization middleware
3. Before/After examples
"""

from __future__ import annotations

import logging
from typing import Any, Callable, Optional

logger = logging.getLogger("security.access_control")


# ═══════════════════════════════════════════════════════════════════
# 1. Core authorization check
# ═══════════════════════════════════════════════════════════════════


class AccessDeniedError(PermissionError):
    """Raised when a user tries to access a resource they don't own."""

    def __init__(self, user_id: Any, resource_owner_id: Any, resource_type: str):
        self.user_id = user_id
        self.resource_owner_id = resource_owner_id
        self.resource_type = resource_type
        super().__init__(
            f"User '{user_id}' attempted to access {resource_type} "
            f"owned by '{resource_owner_id}' — blocked"
        )


def verify_ownership(
    *,
    requesting_user_id: Any,
    resource_owner_id: Any,
    resource_type: str = "resource",
    admins_can_bypass: bool = False,
    is_admin: bool = False,
) -> None:
    """Verify that *requesting_user_id* owns the resource.

    Raises ``AccessDeniedError`` if not.

    Args:
        requesting_user_id: The authenticated user's ID.
        resource_owner_id: The user ID that owns the target resource.
        resource_type: Human-readable type for error messages.
        admins_can_bypass: If True, admin users bypass the check.
        is_admin: Whether the requesting user has admin privileges.
    """
    if admins_can_bypass and is_admin:
        return

    if str(requesting_user_id) != str(resource_owner_id):
        raise AccessDeniedError(
            user_id=requesting_user_id,
            resource_owner_id=resource_owner_id,
            resource_type=resource_type,
        )


# ═══════════════════════════════════════════════════════════════════
# 2. Decorator for ownership checks
# ═══════════════════════════════════════════════════════════════════


def require_ownership(
    user_id_arg: str = "user_id",
    owner_id_arg: str = "target_user_id",
    resource_type: str = "user profile",
    admins_can_bypass: bool = False,
) -> Callable:
    """Decorator that checks horizontal access control on a handler.

    Usage:
        @app.route("/api/users/<target_user_id>/profile")
        @require_ownership(user_id_arg="current_user", owner_id_arg="target_user_id")
        def get_user_profile(current_user, target_user_id):
            ...

    The decorator expects the wrapped function to receive both
    ``user_id_arg`` and ``owner_id_arg`` as keyword arguments.
    """
    def decorator(func: Callable) -> Callable:
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            requesting_user = kwargs.get(user_id_arg)
            resource_owner = kwargs.get(owner_id_arg)

            if requesting_user is None or resource_owner is None:
                raise ValueError(
                    f"require_ownership: could not find '{user_id_arg}' or "
                    f"'{owner_id_arg}' in handler arguments"
                )

            # Extract admin flag from function kwargs or context
            is_admin = kwargs.get("is_admin", False)

            verify_ownership(
                requesting_user_id=requesting_user,
                resource_owner_id=resource_owner,
                resource_type=resource_type,
                admins_can_bypass=admins_can_bypass,
                is_admin=is_admin,
            )

            return func(*args, **kwargs)
        return wrapper
    return decorator


# ═══════════════════════════════════════════════════════════════════
# 3. Before / After example
# ═══════════════════════════════════════════════════════════════════

# B E F O R E  (vulnerable — horizontal privesc):
#
#   @app.route("/api/users/<user_id>/profile")
#   def get_user_profile(user_id):
#       profile = db.users.find_one({"_id": user_id})
#       # ❌ No check that current user == profile owner!
#       return jsonify(profile)
#
#   # Attacker calls:  GET /api/users/456/profile  → gets another user's data
#
# A F T E R  (fixed):
#
#   @app.route("/api/users/<target_user_id>/profile")
#   def get_user_profile(target_user_id):
#       current_user_id = get_current_user_id()  # from session/auth
#       verify_ownership(
#           requesting_user_id=current_user_id,
#           resource_owner_id=target_user_id,
#           resource_type="user profile",
#       )
#       profile = db.users.find_one({"_id": target_user_id})
#       return jsonify(profile)


# ═══════════════════════════════════════════════════════════════════
# 4. Self-test
# ═══════════════════════════════════════════════════════════════════


def _test():
    # Happy path: user accesses own resource
    verify_ownership(
        requesting_user_id=42,
        resource_owner_id=42,
        resource_type="profile",
    )

    # Happy path: admin bypass
    verify_ownership(
        requesting_user_id=1,
        resource_owner_id=42,
        resource_type="profile",
        admins_can_bypass=True,
        is_admin=True,
    )

    # Blocked: user accesses another user's resource
    try:
        verify_ownership(
            requesting_user_id=1,
            resource_owner_id=42,
            resource_type="profile",
        )
        assert False, "Should have raised AccessDeniedError"
    except AccessDeniedError:
        pass

    # Blocked: admin without bypass
    try:
        verify_ownership(
            requesting_user_id=1,
            resource_owner_id=42,
            resource_type="profile",
            admins_can_bypass=False,
            is_admin=True,
        )
        assert False, "Should have raised AccessDeniedError"
    except AccessDeniedError:
        pass

    print("Horizontal privilege escalation fix: all tests passed")


if __name__ == "__main__":
    _test()
