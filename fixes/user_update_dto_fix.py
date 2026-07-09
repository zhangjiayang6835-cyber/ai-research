"""
Fix for Issue #206 (variant): Mass Assignment in User Profile Update
→ Privilege Escalation

Vulnerability
-------------
The user profile update endpoint bound the entire incoming request payload
directly onto the ``User`` model, e.g.::

    user.update(**request.json)

An attacker could append ``role="admin"`` or ``is_admin=true`` to the
request body and be granted elevated privileges, because nothing filtered
out sensitive fields before they were applied via ``setattr``.

Fix
---
Introduce ``UserUpdateDTO`` — a small, explicit whitelist of the fields a
user is allowed to self-update. ``User.update()`` no longer accepts an
arbitrary mapping of kwargs; it only accepts a ``UserUpdateDTO`` instance,
and the DTO itself is the single place where the whitelist is enforced
(deny by default). Any attempt to smuggle a privileged/unknown field —
either directly or via ``UserUpdateDTO.from_request`` — raises
``MassAssignmentError`` instead of silently being dropped or, worse,
applied.

Usage
-----
    dto = UserUpdateDTO.from_request(request.json)
    user.update(dto)

Attempting::

    UserUpdateDTO.from_request({"name": "x", "role": "admin"})

raises ``MassAssignmentError`` naming the offending field(s).
"""

from __future__ import annotations

from dataclasses import dataclass, fields as dataclass_fields
from typing import Any, ClassVar, Mapping, Optional


class MassAssignmentError(ValueError):
    """Raised when a payload attempts to write a non-whitelisted field."""

    def __init__(self, message: str, offending: tuple[str, ...] = ()):
        super().__init__(message)
        self.offending = offending


# Fields the server must always control. Never assignable through the DTO,
# regardless of what the client sends.
IMMUTABLE_FIELDS: frozenset[str] = frozenset(
    {
        "id",
        "uuid",
        "created_at",
        "updated_at",
        "password_hash",
        "password_salt",
        "email_verified_at",
    }
)

# Fields that grant elevated privileges. Never assignable through the
# self-service profile update DTO.
PRIVILEGED_FIELDS: frozenset[str] = frozenset(
    {
        "role",
        "roles",
        "is_admin",
        "is_superuser",
        "is_staff",
        "permissions",
        "scopes",
        "tenant_id",
        "account_type",
    }
)

_IMMUTABLE_CI = frozenset(f.lower() for f in IMMUTABLE_FIELDS)
_PRIVILEGED_CI = frozenset(f.lower() for f in PRIVILEGED_FIELDS)


@dataclass
class UserUpdateDTO:
    """Whitelist of fields a user may set on their own profile.

    Only attributes declared here can ever be written by ``User.update()``.
    Anything else — including sensitive fields like ``role`` or
    ``is_admin`` — is rejected at construction time via
    :meth:`from_request`, and is simply not a settable attribute on this
    dataclass at all.
    """

    name: Optional[str] = None
    display_name: Optional[str] = None
    avatar_url: Optional[str] = None
    locale: Optional[str] = None
    timezone: Optional[str] = None
    bio: Optional[str] = None

    # Explicit allow-list, derived from the dataclass fields themselves so
    # it can never drift out of sync with what is actually settable.
    ALLOWED_FIELDS: ClassVar[frozenset[str]] = frozenset(
        f.name for f in dataclass_fields("UserUpdateDTO")  # type: ignore[arg-type]
    ) if False else frozenset()  # placeholder, replaced below

    @classmethod
    def allowed_fields(cls) -> frozenset[str]:
        return frozenset(f.name for f in dataclass_fields(cls))

    @classmethod
    def from_request(cls, payload: Mapping[str, Any] | None) -> "UserUpdateDTO":
        """Build a DTO from a raw request payload, rejecting anything not
        on the whitelist. This is the ONLY supported entry point for
        turning untrusted input into a DTO — it fails closed.
        """
        if payload is None:
            return cls()
        if not isinstance(payload, Mapping):
            raise MassAssignmentError(
                "Payload must be a mapping/object", offending=(str(type(payload)),)
            )

        allowed = cls.allowed_fields()
        forbidden: list[str] = []
        unknown: list[str] = []
        clean: dict[str, Any] = {}

        for raw_key, value in payload.items():
            if not isinstance(raw_key, str):
                forbidden.append(repr(raw_key))
                continue
            key = raw_key.strip()
            key_ci = key.lower()

            if key_ci in _IMMUTABLE_CI or key_ci in _PRIVILEGED_CI:
                forbidden.append(key)
                continue

            if key not in allowed:
                unknown.append(key)
                continue

            clean[key] = value

        if forbidden:
            raise MassAssignmentError(
                "Payload attempts to set restricted/privileged fields",
                offending=tuple(sorted(set(forbidden))),
            )
        if unknown:
            raise MassAssignmentError(
                "Payload contains unknown fields",
                offending=tuple(sorted(set(unknown))),
            )

        return cls(**clean)

    def as_dict(self) -> dict[str, Any]:
        """Only the fields that were actually provided (non-None), so a
        partial update doesn't clobber existing values with ``None``."""
        return {
            f.name: getattr(self, f.name)
            for f in dataclass_fields(self)
            if getattr(self, f.name) is not None
        }


# Fix the placeholder above cleanly (dataclass class-var trick doesn't play
# well at class-definition time); recompute once the class exists.
UserUpdateDTO.ALLOWED_FIELDS = UserUpdateDTO.allowed_fields()


class User:
    """Minimal User model demonstrating the safe ``update()`` contract.

    Sensitive attributes (``role``, ``is_admin``, ``id``, ...) live on the
    model but are intentionally NOT reachable through ``update()`` — the
    only mutation path accepts a :class:`UserUpdateDTO`, whose whitelist is
    the sole source of truth for what a user may change about themselves.
    """

    def __init__(
        self,
        id: int,
        name: str = "",
        display_name: str = "",
        avatar_url: str = "",
        locale: str = "en",
        timezone: str = "UTC",
        bio: str = "",
        role: str = "user",
        is_admin: bool = False,
    ) -> None:
        self.id = id
        self.name = name
        self.display_name = display_name
        self.avatar_url = avatar_url
        self.locale = locale
        self.timezone = timezone
        self.bio = bio
        self.role = role
        self.is_admin = is_admin

    def update(self, dto: UserUpdateDTO) -> "User":
        """Apply a whitelisted profile update.

        ``dto`` MUST be a :class:`UserUpdateDTO`. This intentionally does
        NOT accept ``**kwargs`` or a raw ``dict`` — doing so would
        reintroduce the mass-assignment vector this fix closes. Callers
        working with raw request data must go through
        ``UserUpdateDTO.from_request(payload)`` first, which enforces the
        whitelist and raises :class:`MassAssignmentError` on any attempt to
        set a privileged/unknown field.
        """
        if not isinstance(dto, UserUpdateDTO):
            raise TypeError(
                "User.update() requires a UserUpdateDTO; raw dict/kwargs "
                "mass-assignment is not supported"
            )

        for key, value in dto.as_dict().items():
            # Defense in depth: even though UserUpdateDTO can only ever
            # contain whitelisted fields, re-verify before setattr.
            if key not in UserUpdateDTO.ALLOWED_FIELDS:
                raise MassAssignmentError(
                    f"Field {key!r} is not updatable via UserUpdateDTO",
                    offending=(key,),
                )
            setattr(self, key, value)
        return self


if __name__ == "__main__":  # pragma: no cover
    # Happy path
    u = User(id=1, name="alice", role="user", is_admin=False)
    dto = UserUpdateDTO.from_request({"name": "Alice", "locale": "en-US"})
    u.update(dto)
    assert u.name == "Alice" and u.locale == "en-US"
    assert u.role == "user" and u.is_admin is False

    # Privilege escalation attempt must be rejected before it ever reaches
    # User.update().
    for evil in (
        {"name": "x", "role": "admin"},
        {"name": "x", "is_admin": True},
        {"name": "x", "IsAdmin": True},
        {"name": "x", "ROLE": "admin"},
        {"name": "x", "id": 999},
        {"name": "x", "unexpected_field": 1},
    ):
        try:
            UserUpdateDTO.from_request(evil)
        except MassAssignmentError:
            pass
        else:
            raise AssertionError(f"mass assignment payload accepted: {evil}")

    assert u.role == "user" and u.is_admin is False and u.id == 1
    print("user_update_dto_fix: self-test passed")
