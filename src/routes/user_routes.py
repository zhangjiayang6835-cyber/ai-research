from __future__ import annotations

import logging
from typing import Any, Mapping

from src.models.user import (
    MassAssignmentError,
    USER_ADMIN_POLICY,
    USER_SELF_POLICY,
    sanitize_payload,
)

logger = logging.getLogger("security.mass_assignment")

# ---------------------------------------------------------------------------
# Simulated request/auth context — replace with real framework objects
# ---------------------------------------------------------------------------

class Request:  # placeholder for Flask/FastAPI request
    def get_json(self) -> dict:  # pragma: no cover
        ...


class AuthContext:  # placeholder for auth middleware
    user_id: str
    is_admin: bool


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _jsonify(payload: dict) -> dict:  # pragma: no cover
    return payload


def _require_auth(request: Any) -> AuthContext:
    """Stub — replace with real auth decorator / dependency injection."""
    raise NotImplementedError("Wire up your real auth middleware here")


# ---------------------------------------------------------------------------
# Routes — hardened against mass-assignment
# ---------------------------------------------------------------------------

def update_profile(request: Any, current_user: Any) -> dict:
    """PUT /api/user/profile — self-service profile update.

    Uses the USER_SELF_POLICY allow-list. Privileged fields (role, is_admin,
    etc.) are always rejected regardless of what the client sends.
    """
    raw_data = request.get_json()
    if not isinstance(raw_data, dict):
        return {"error": "Request body must be a JSON object"}

    try:
        clean = sanitize_payload(raw_data, USER_SELF_POLICY, actor_id=current_user.id)
    except MassAssignmentError as exc:
        logger.warning(
            "profile_update_rejected user=%s offending=%s reason=%s",
            current_user.id, exc.offending, str(exc),
        )
        return {"error": str(exc), "offending_fields": list(exc.offending)}

    for key, value in clean.items():
        setattr(current_user, key, value)
    current_user.save()

    return {"status": "ok", "updated_fields": list(clean.keys())}


def admin_update_user(request: Any, target_user: Any, admin_user: Any) -> dict:
    """PUT /api/admin/user/:id — admin-only update.

    Uses USER_ADMIN_POLICY which permits privileged fields, but still
    rejects immutable fields and unknown/suspicious keys.
    """
    raw_data = request.get_json()
    if not isinstance(raw_data, dict):
        return {"error": "Request body must be a JSON object"}

    try:
        clean = sanitize_payload(raw_data, USER_ADMIN_POLICY, actor_id=admin_user.id)
    except MassAssignmentError as exc:
        logger.warning(
            "admin_update_rejected admin=%s target=%s offending=%s reason=%s",
            admin_user.id, target_user.id, exc.offending, str(exc),
        )
        return {"error": str(exc), "offending_fields": list(exc.offending)}

    for key, value in clean.items():
        setattr(target_user, key, value)
    target_user.save()

    logger.info(
        "admin_user_updated admin=%s target=%s fields=%s",
        admin_user.id, target_user.id, list(clean.keys()),
    )
    return {"status": "ok", "updated_fields": list(clean.keys())}
