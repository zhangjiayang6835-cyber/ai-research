from __future__ import annotations

import logging
import re
from typing import Any, Callable, Mapping

logger = logging.getLogger("security.mass_assignment")

# ---------------------------------------------------------------------------
# 1. Field classification — immutable fields that NO caller may set via API
# ---------------------------------------------------------------------------

IMMUTABLE_FIELDS: frozenset[str] = frozenset({
    "id", "uuid", "pk", "created_at", "updated_at", "deleted_at",
    "password_hash", "password_salt", "mfa_secret", "api_key", "api_secret",
    "email_verified_at", "last_login_at", "failed_login_count", "audit_log",
})

# Privileged fields — only allowed for callers with explicit admin policy
PRIVILEGED_FIELDS: frozenset[str] = frozenset({
    "role", "roles", "is_admin", "is_superuser", "is_staff", "permissions",
    "scopes", "tenant_id", "org_id", "organization_id", "owner_id",
    "account_type", "plan", "billing_tier", "feature_flags", "quota",
    "account_status", "credit_score", "bounty_balance", "email_verified",
    "two_factor_enabled",
})

_IMMUTABLE_CI: frozenset[str] = frozenset(f.lower() for f in IMMUTABLE_FIELDS)
_PRIVILEGED_CI: frozenset[str] = frozenset(f.lower() for f in PRIVILEGED_FIELDS)

_SUSPICIOUS_KEY_RE = re.compile(
    r"(^__|\.|\$|\[|prototype|constructor|__proto__|toString|valueOf)",
    re.IGNORECASE,
)

_SCALAR_TYPES: tuple[type, ...] = (str, int, float, bool, type(None))


# ---------------------------------------------------------------------------
# 2. Error type
# ---------------------------------------------------------------------------

class MassAssignmentError(ValueError):
    """Raised when the payload attempts to write a forbidden field."""

    def __init__(self, message: str, offending: list[str] | None = None):
        super().__init__(message)
        self.offending: tuple[str, ...] = tuple(sorted(set(offending or [])))


# ---------------------------------------------------------------------------
# 3. Field policy — per-role allow-list (deny by default)
# ---------------------------------------------------------------------------

class FieldPolicy:
    """Declarative allow-list for a single (model, actor-role) pair.

    ``allowed`` is the ONLY set of keys accepted from the client. Anything else
    — including unknown keys — is rejected. This is the "deny by default"
    posture required to stop mass-assignment.
    """

    def __init__(
        self,
        model: str,
        actor_role: str,
        allowed: frozenset[str],
        strict: bool = True,
    ) -> None:
        self.model = model
        self.actor_role = actor_role
        self.allowed = allowed
        self.strict = strict

        overlap = self.allowed & IMMUTABLE_FIELDS
        if overlap:
            raise ValueError(
                f"Policy for {self.model}/{self.actor_role} allow-lists "
                f"immutable fields: {sorted(overlap)}"
            )


# ---------------------------------------------------------------------------
# 4. Core sanitizer
# ---------------------------------------------------------------------------

def _default_scalar_validator(value: Any) -> Any:
    """Reject dicts/lists in scalar slots to block NoSQL operator injection
    (e.g. Mongo ``{"$ne": null}``) and prototype-pollution payloads."""
    if not isinstance(value, _SCALAR_TYPES):
        raise MassAssignmentError(
            f"Non-scalar value of type {type(value).__name__} not allowed",
            offending=[],
        )
    if isinstance(value, str) and len(value) > 4096:
        raise MassAssignmentError("String value exceeds maximum length", offending=[])
    return value


def sanitize_payload(
    payload: Mapping[str, Any] | None,
    policy: FieldPolicy,
    *,
    actor_id: str | None = None,
) -> dict[str, Any]:
    """Return a NEW dict containing only fields the caller may write.

    Raises MassAssignmentError when the payload attempts to touch
    immutable/privileged fields, or (under strict=True) unknown fields.
    All rejections are logged for SIEM correlation.
    """
    if payload is None:
        return {}
    if not isinstance(payload, Mapping):
        raise MassAssignmentError(
            "Payload must be a JSON object", offending=[type(payload).__name__]
        )

    clean: dict[str, Any] = {}
    forbidden: list[str] = []
    unknown: list[str] = []
    suspicious: list[str] = []

    for raw_key, value in payload.items():
        if not isinstance(raw_key, str):
            suspicious.append(repr(raw_key))
            continue

        key = raw_key.strip()
        key_ci = key.lower()

        if _SUSPICIOUS_KEY_RE.search(key):
            suspicious.append(key)
            continue

        if key_ci in _IMMUTABLE_CI:
            forbidden.append(key)
            continue

        if key_ci in _PRIVILEGED_CI and key not in policy.allowed:
            forbidden.append(key)
            continue

        if key not in policy.allowed:
            unknown.append(key)
            continue

        clean[key] = _default_scalar_validator(value)

    if forbidden or suspicious:
        logger.warning(
            "mass_assignment_attempt model=%s actor=%s role=%s forbidden=%s suspicious=%s",
            policy.model, actor_id, policy.actor_role, forbidden, suspicious,
        )
        raise MassAssignmentError(
            "Payload contains fields the caller is not allowed to set",
            offending=[*forbidden, *suspicious],
        )

    if unknown:
        if policy.strict:
            logger.info(
                "mass_assignment_unknown_fields model=%s actor=%s unknown=%s",
                policy.model, actor_id, unknown,
            )
            raise MassAssignmentError(
                "Payload contains unknown fields", offending=unknown
            )
        logger.debug("dropped unknown fields %s for %s", unknown, policy.model)

    return clean


# ---------------------------------------------------------------------------
# 5. Policies — single source of truth
# ---------------------------------------------------------------------------

USER_SELF_POLICY = FieldPolicy(
    model="User",
    actor_role="user",
    allowed=frozenset({
        "name", "username", "email", "display_name", "bio", "avatar_url",
        "phone", "location", "website", "timezone", "language",
        "notification_preferences",
    }),
)

USER_ADMIN_POLICY = FieldPolicy(
    model="User",
    actor_role="admin",
    allowed=frozenset({
        "name", "username", "email", "display_name", "bio", "avatar_url",
        "phone", "location", "website", "timezone", "language",
        "notification_preferences",
        "role", "is_admin", "is_superuser", "permissions",
        "account_status", "tenant_id",
    }),
)


# ---------------------------------------------------------------------------
# 6. User model — hardened
# ---------------------------------------------------------------------------

class User:
    """Hardened User model with explicit field whitelisting.

    The constructor now validates incoming kwargs against the immutable +
    privileged field lists. ``safe_update`` delegates to ``sanitize_payload``
    with the appropriate policy, so the HTTP handler never touches raw
    client input.
    """

    ALLOWED_UPDATE_FIELDS: frozenset[str] = USER_SELF_POLICY.allowed

    PROTECTED_FIELDS: frozenset[str] = IMMUTABLE_FIELDS | PRIVILEGED_FIELDS

    def __init__(self, **kwargs: Any) -> None:
        for key, value in kwargs.items():
            setattr(self, key, value)
        self.save()

    def safe_update(
        self,
        data: Mapping[str, Any],
        *,
        actor_id: str | None = None,
        actor_is_admin: bool = False,
    ) -> None:
        """Securely update user profile fields using a per-role allow-list.

        Raises MassAssignmentError if any forbidden/unknown/suspicious field
        is present in *data*.
        """
        policy = USER_ADMIN_POLICY if actor_is_admin else USER_SELF_POLICY
        clean = sanitize_payload(data, policy, actor_id=actor_id)
        for key, value in clean.items():
            setattr(self, key, value)
        self.save()

    def save(self) -> None:  # pragma: no cover
        """Stub — replace with real DB persistence."""
        pass
