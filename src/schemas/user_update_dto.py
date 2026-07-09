"""
User Update DTO (Data Transfer Object)

Implements whitelist-based parameter binding to prevent
mass assignment vulnerabilities (e.g., privilege escalation
via role=admin or is_admin=true injection).
"""

from dataclasses import dataclass, field
from typing import Optional, Dict, Any

# Whitelist of fields allowed for user self-update
ALLOWED_UPDATE_FIELDS = {
    'display_name',
    'email',
    'bio',
    'avatar_url',
    'timezone',
    'language',
    'notification_preferences',
}

# Explicitly forbidden fields that must NEVER be mass-assigned
FORBIDDEN_FIELDS = {
    'role',
    'is_admin',
    'is_superuser',
    'permissions',
    'account_status',
    'credit_score',
    'bounty_balance',
    'verified',
    'internal_notes',
}


@dataclass
class UserUpdateDTO:
    """Safe DTO for user profile updates with whitelist validation."""
    display_name: Optional[str] = None
    email: Optional[str] = None
    bio: Optional[str] = None
    avatar_url: Optional[str] = None
    timezone: Optional[str] = None
    language: Optional[str] = None
    notification_preferences: Optional[Dict[str, Any]] = None

    _allowed_fields: set = field(default_factory=lambda: ALLOWED_UPDATE_FIELDS, init=False, repr=False)