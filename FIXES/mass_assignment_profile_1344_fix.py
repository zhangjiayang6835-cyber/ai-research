"""
Fix for Issue #1344 — Mass Assignment in User Profile Update
=============================================================

Vulnerability
-------------
The user profile update endpoint directly binds all request parameters
to the user model without filtering. An attacker can include sensitive
fields like ``role``, ``is_admin``, or ``permissions`` in the update
payload to escalate privileges.

Root Cause
----------
The API endpoint calls ``user.update(attrs)`` or
``Model.bind(request.params)`` without an allow-list of updatable
fields. Privilege-related fields are not protected.

Fix Strategy
------------
1. Define an explicit allow-list of fields users may update.
2. Strip disallowed and sensitive fields before any database operation.
3. Validate field types and lengths.
4. Log attempts to set privilege fields for security monitoring.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, FrozenSet, Optional, Set

logger = logging.getLogger(__name__)


# ── Configuration ─────────────────────────────────────────────────────

# Fields that users are allowed to update via profile API
ALLOWED_PROFILE_FIELDS: FrozenSet[str] = frozenset({
    "display_name",
    "bio",
    "timezone",
    "avatar_url",
    "marketing_opt_in",
})

# Privileged fields that MUST NOT be set via user-facing API
PRIVILEGED_FIELDS: FrozenSet[str] = frozenset({
    "role",
    "is_admin",
    "permissions",
    "tenant_id",
    "user_id",
    "account_status",
    "subscription_tier",
})

# Type validators for allowed fields
FIELD_VALIDATORS: Dict[str, callable] = {
    "display_name": lambda v: isinstance(v, str) and 1 <= len(v) <= 100,
    "bio": lambda v: isinstance(v, str) and len(v) <= 500,
    "timezone": lambda v: isinstance(v, str) and len(v) <= 50,
    "avatar_url": lambda v: isinstance(v, str) and len(v) <= 500,
    "marketing_opt_in": lambda v: isinstance(v, bool),
}


class MassAssignmentViolation(ValueError):
    """Raised when a mass assignment attempt contains privileged fields."""

    def __init__(self, fields: Set[str]):
        self.fields = fields
        super().__init__(f"Mass assignment detected: {fields}")


class FieldValidationError(ValueError):
    """Raised when a field value fails type validation."""


# ── Field Name Normalization ─────────────────────────────────────────

def _normalize_field_name(name: str) -> str:
    """Normalize field names to detect case/hyphen variants.

    Converts to lowercase and replaces hyphens/underscores.
    """
    normalized = name.strip().lower().replace("-", "_")
    return normalized


def _detect_privileged_fields(payload: Dict[str, Any]) -> Set[str]:
    """Detect any privileged fields in the payload.

    Handles case-insensitive and dash/underscore variants.
    """
    detected: Set[str] = set()
    # Build normalized lookup for privileged fields
    privileged_normalized: Dict[str, str] = {
        _normalize_field_name(f): f for f in PRIVILEGED_FIELDS
    }

    for key in payload:
        normalized_key = _normalize_field_name(key)
        if normalized_key in privileged_normalized:
            detected.add(key)

    return detected


# ── Profile Sanitization ─────────────────────────────────────────────

def sanitize_profile_update(payload: Dict[str, Any]) -> Dict[str, Any]:
    """Sanitize a profile update payload.

    Strips disallowed fields and raises on sensitive fields.

    Args:
        payload: The raw request payload.

    Returns:
        Sanitized payload with only allowed fields.

    Raises:
        MassAssignmentViolation: If privileged fields are detected.
        FieldValidationError: If field values fail validation.
    """
    if not isinstance(payload, dict):
        raise MassAssignmentViolation("Payload must be a dictionary")

    # Step 1: Detect privileged fields
    privileged = _detect_privileged_fields(payload)
    if privileged:
        logger.warning(
            "Mass assignment attempt detected: %s", privileged
        )
        raise MassAssignmentViolation(privileged)

    # Step 2: Filter to allowed fields only
    sanitized: Dict[str, Any] = {}
    for key, value in payload.items():
        normalized = _normalize_field_name(key)

        # Check if the normalized key matches an allowed field
        allowed_match = None
        for allowed in ALLOWED_PROFILE_FIELDS:
            if _normalize_field_name(allowed) == normalized:
                allowed_match = allowed
                break

        if allowed_match is None:
            # Silently skip unknown fields
            continue

        # Step 3: Validate field value
        validator = FIELD_VALIDATORS.get(allowed_match)
        if validator and not validator(value):
            raise FieldValidationError(
                f"Invalid value for field '{allowed_match}': {value!r}"
            )

        sanitized[allowed_match] = value

    return sanitized


# ── Apply Update ─────────────────────────────────────────────────────

def apply_profile_update(
    user: Dict[str, Any],
    payload: Dict[str, Any],
) -> Dict[str, Any]:
    """Apply a sanitized profile update to a user object.

    Args:
        user: The current user data dict.
        payload: The sanitized update payload.

    Returns:
        Updated user dict.

    Raises:
        MassAssignmentViolation: If payload contains privileged fields.
        FieldValidationError: If field values are invalid.
    """
    sanitized = sanitize_profile_update(payload)

    # Apply updates
    updated = dict(user)
    updated.update(sanitized)

    # Safety check: ensure privileged fields weren't modified
    for field in PRIVILEGED_FIELDS:
        if field in payload:
            raise MassAssignmentViolation({field})

    return updated


# ── User Profile Model (for testing) ─────────────────────────────────

class UserProfile:
    """Minimal user profile model for testing mass assignment fix."""

    ALLOWED = ALLOWED_PROFILE_FIELDS

    def __init__(
        self,
        user_id: str,
        display_name: str = "",
        bio: str = "",
        timezone: str = "UTC",
        avatar_url: str = "",
        marketing_opt_in: bool = False,
        role: str = "member",
        is_admin: bool = False,
        tenant_id: str = "",
    ):
        self.user_id = user_id
        self.display_name = display_name
        self.bio = bio
        self.timezone = timezone
        self.avatar_url = avatar_url
        self.marketing_opt_in = marketing_opt_in
        self.role = role
        self.is_admin = is_admin
        self.tenant_id = tenant_id

    def update(self, payload: Dict[str, Any]) -> None:
        """Apply a sanitized update to this profile.

        Args:
            payload: Raw update payload.

        Raises:
            MassAssignmentViolation: If privileged fields are detected.
            FieldValidationError: If field values are invalid.
        """
        sanitized = sanitize_profile_update(payload)
        for key, value in sanitized.items():
            setattr(self, key, value)
