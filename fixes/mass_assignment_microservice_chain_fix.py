"""Mass-assignment guard for issue #256.

The vulnerable pattern is binding an untrusted profile-update payload directly
onto a shared user/account object. In a microservice chain, attacker supplied
fields such as ``role``, ``is_admin``, ``tenant_id``, or ``permissions`` can
propagate to downstream authorization services and become a privilege
escalation. This module keeps the trust boundary at the HTTP edge: only an
explicit public allowlist is writable, and identity/privilege fields are always
server-controlled.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from typing import Any, Mapping


class MassAssignmentViolation(ValueError):
    """Raised when a payload attempts to write fields outside policy."""

    def __init__(self, message: str, fields: list[str]) -> None:
        super().__init__(message)
        self.fields = tuple(sorted(set(fields)))


@dataclass(frozen=True)
class Account:
    user_id: str
    email: str
    tenant_id: str
    role: str
    is_admin: bool = False
    display_name: str = ""
    bio: str = ""
    timezone: str = "UTC"
    marketing_opt_in: bool = False


PUBLIC_PROFILE_SCHEMA: Mapping[str, type] = {
    "display_name": str,
    "bio": str,
    "timezone": str,
    "marketing_opt_in": bool,
}

SERVER_CONTROLLED_FIELDS = {
    "id",
    "user_id",
    "email",
    "tenant_id",
    "org_id",
    "organization_id",
    "account_id",
    "role",
    "roles",
    "is_admin",
    "is_superuser",
    "is_staff",
    "permissions",
    "scopes",
    "plan",
    "billing_tier",
    "quota",
    "password",
    "password_hash",
    "mfa_secret",
    "api_key",
    "created_at",
    "updated_at",
}


def apply_public_profile_update(account: Account, payload: Mapping[str, Any]) -> Account:
    """Return an updated account after validating a public profile payload."""

    clean = sanitize_public_profile_update(payload)
    return replace(account, **clean)


def sanitize_public_profile_update(payload: Mapping[str, Any]) -> dict[str, Any]:
    """Validate and filter a user-controlled update payload.

    Unknown fields are rejected rather than silently dropped. Failing closed
    lets callers log attacks and prevents later microservices from accepting a
    partially-mutated account object.
    """

    if not isinstance(payload, Mapping):
        raise MassAssignmentViolation("payload must be an object", ["<payload>"])

    forbidden: list[str] = []
    clean: dict[str, Any] = {}
    for raw_key, value in payload.items():
        if not isinstance(raw_key, str):
            forbidden.append("<non-string-key>")
            continue

        canonical = _canonical_key(raw_key)
        if _is_suspicious_key(raw_key) or canonical in SERVER_CONTROLLED_FIELDS:
            forbidden.append(raw_key)
            continue

        expected_type = PUBLIC_PROFILE_SCHEMA.get(canonical)
        if expected_type is None:
            forbidden.append(raw_key)
            continue

        if not isinstance(value, expected_type) or isinstance(value, (dict, list, tuple, set)):
            forbidden.append(raw_key)
            continue

        if isinstance(value, str) and len(value) > 512:
            forbidden.append(raw_key)
            continue

        clean[canonical] = value

    if forbidden:
        raise MassAssignmentViolation("mass-assignment payload contains forbidden fields", forbidden)

    return clean


def build_auth_profile_event(account: Account) -> dict[str, Any]:
    """Build the downstream auth event from trusted account state only."""

    return {
        "user_id": account.user_id,
        "email": account.email,
        "tenant_id": account.tenant_id,
        "role": account.role,
        "is_admin": account.is_admin,
        "profile": {
            "display_name": account.display_name,
            "bio": account.bio,
            "timezone": account.timezone,
            "marketing_opt_in": account.marketing_opt_in,
        },
    }


def vulnerable_bind(account: Account, payload: Mapping[str, Any]) -> Account:
    """Model the dangerous ORM-style bind used by tests to prove the bug."""

    updates = {key: value for key, value in payload.items() if hasattr(account, str(key))}
    return replace(account, **updates)


def _canonical_key(key: str) -> str:
    return key.strip().lower().replace("-", "_")


def _is_suspicious_key(key: str) -> bool:
    compact = key.replace("-", "_").lower()
    return (
        "__" in compact
        or "." in key
        or "[" in key
        or "]" in key
        or "$" in key
        or "prototype" in compact
        or "constructor" in compact
        or any(ord(ch) < 32 for ch in key)
    )


__all__ = [
    "Account",
    "MassAssignmentViolation",
    "apply_public_profile_update",
    "build_auth_profile_event",
    "sanitize_public_profile_update",
    "vulnerable_bind",
]
