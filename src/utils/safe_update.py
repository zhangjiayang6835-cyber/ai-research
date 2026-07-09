"""
Safe parameter binding utilities to prevent mass assignment.

Provides helper functions to filter request parameters against
a whitelist before passing them to model update methods.
"""

from typing import Dict, Any, Set, Optional
import logging

logger = logging.getLogger(__name__)

# Default sensitive fields that should never be mass-assigned
DEFAULT_FORBIDDEN_FIELDS: Set[str] = {
    'role', 'is_admin', 'is_superuser', 'admin',
    'permissions', 'privileges', 'access_level',
    'account_status', 'suspended', 'banned',
    'credit_score', 'balance', 'bounty_balance',
    'verified', 'email_verified', 'kyc_status',
    'password_hash', 'password', 'secret',
    'api_key', 'token', 'session_id',
    'internal_notes', 'admin_notes',
    'created_at', 'updated_at', 'last_login',
    'id', 'uuid', 'user_id',
}


def filter_params(
    params: Dict[str, Any],
    allowed_fields: Set[str],
    forbidden_fields: Optional[Set[str]] = None
) -> Dict[str, Any]:
    """
    Filter a dictionary of parameters, keeping only keys present
    in the allowed_fields whitelist and rejecting any forbidden fields.

    Args:
        params: Raw request parameters (e.g., request.json or request.form)
        allowed_fields: Set of field names permitted for this operation
        forbidden_fields: Optional extra set of fields to explicitly reject

    Returns:
        Cleaned dictionary containing only whitelisted parameters.

    Raises:
        ValueError: If any forbidden field is detected in params.
    """
    if forbidden_fields is None:
        forbidden_fields = DEFAULT_FORBIDDEN_FIELDS

    # Detect and reject forbidden fields
    detected_forbidden = set(params.keys()) & forbidden_fields
    if detected_forbidden:
        logger.warning(
            f"Mass assignment attempt detected! Forbidden fields: {detected_forbidden}"
        )
        raise ValueError(
            f"Update contains forbidden fields: {', '.join(sorted(detected_forbidden))}"
        )

    # Return only whitelisted parameters
    return {k: v for k, v in params.items() if k in allowed_fields}