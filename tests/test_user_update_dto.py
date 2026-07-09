"""
Tests for Issue #206 (variant): Mass Assignment in User Profile Update
→ Privilege Escalation.

Verifies that ``User.update()`` only accepts a whitelisted
``UserUpdateDTO`` and that privileged/unknown/immutable fields can never
be mass-assigned onto the model, either directly or via
``UserUpdateDTO.from_request``.
"""

import pytest

from fixes.user_update_dto_fix import (
    MassAssignmentError,
    User,
    UserUpdateDTO,
)


def make_user() -> User:
    return User(
        id=42,
        name="alice",
        display_name="Alice",
        avatar_url="https://example.com/a.png",
        locale="en",
        timezone="UTC",
        bio="hi",
        role="user",
        is_admin=False,
    )


def test_legitimate_update_applies_whitelisted_fields():
    user = make_user()
    dto = UserUpdateDTO.from_request(
        {"name": "Alice Cooper", "locale": "en-GB", "bio": "updated bio"}
    )
    user.update(dto)

    assert user.name == "Alice Cooper"
    assert user.locale == "en-GB"
    assert user.bio == "updated bio"
    # Untouched fields remain unchanged.
    assert user.display_name == "Alice"
    assert user.role == "user"
    assert user.is_admin is False


def test_update_requires_dto_instance_not_raw_dict():
    user = make_user()
    with pytest.raises(TypeError):
        user.update({"name": "hacker"})  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "payload",
    [
        {"name": "hacker", "role": "admin"},
        {"name": "hacker", "is_admin": True},
        {"name": "hacker", "is_superuser": True},
        {"name": "hacker", "permissions": ["*"]},
        {"name": "hacker", "tenant_id": 999},
        {"name": "hacker", "IsAdmin": True},   # case variant
        {"name": "hacker", "ROLE": "admin"},   # case variant
    ],
)
def test_privileged_fields_are_rejected(payload):
    user = make_user()

    with pytest.raises(MassAssignmentError) as exc_info:
        UserUpdateDTO.from_request(payload)

    assert exc_info.value.offending
    # The model must remain completely untouched since the DTO never
    # got constructed and update() was never called.
    assert user.role == "user"
    assert user.is_admin is False
    assert user.name == "alice"


@pytest.mark.parametrize(
    "payload",
    [
        {"id": 1},
        {"password_hash": "pwned"},
        {"created_at": "1970-01-01"},
    ],
)
def test_immutable_fields_are_rejected(payload):
    with pytest.raises(MassAssignmentError):
        UserUpdateDTO.from_request(payload)


def test_unknown_fields_are_rejected_fail_closed():
    with pytest.raises(MassAssignmentError) as exc_info:
        UserUpdateDTO.from_request({"name": "ok", "totally_made_up_field": 1})

    assert "totally_made_up_field" in exc_info.value.offending


def test_from_request_with_none_returns_empty_dto():
    dto = UserUpdateDTO.from_request(None)
    assert dto.as_dict() == {}


def test_from_request_rejects_non_mapping_payload():
    with pytest.raises(MassAssignmentError):
        UserUpdateDTO.from_request([("name", "x")])  # type: ignore[arg-type]


def test_update_defense_in_depth_rejects_non_whitelisted_attribute():
    """Even if a caller manually crafts a UserUpdateDTO-like object with an
    extra attribute, User.update() only ever applies whitelisted keys via
    as_dict(), which is derived strictly from the dataclass fields."""
    user = make_user()
    dto = UserUpdateDTO(name="Bob")
    user.update(dto)
    assert user.name == "Bob"
    assert user.role == "user"
    assert user.is_admin is False
