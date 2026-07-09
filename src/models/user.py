from dataclasses import dataclass, field
from typing import Optional, List

# Whitelist of fields allowed for user profile self-update
USER_PROFILE_UPDATE_ALLOWED_FIELDS = {
    'display_name',
    'bio',
    'avatar_url',
    'email',
    'phone',
    'location',
    'website',
    'timezone',
    'language',
    'notification_preferences',
}

# Sensitive fields that must NEVER be mass-assigned
SENSITIVE_FIELDS = {
    'role',
    'is_admin',
    'is_superuser',
    'permissions',
    'account_status',
    'verified',
    'credit_score',
    'bounty_balance',
    'internal_notes',
    'api_key',
    'password_hash',
    'two_factor_secret',
}


@dataclass
class UserProfileUpdateDTO:
    """Data Transfer Object for user profile updates.
    
    Only explicitly whitelisted fields are accepted.
    All other fields are silently discarded to prevent mass assignment attacks.
    """
    display_name: Optional[str] = None
    bio: Optional[str] = None
    avatar_url: Optional[str] = None
    email: Optional[str] = None
    phone: Optional[str] = None
    location: Optional[str] = None
    website: Optional[str] = None
    timezone: Optional[str] = None
    language: Optional[str] = None
    notification_preferences: Optional[dict] = None

    @classmethod
    def from_request(cls, params: dict) -> 'UserProfileUpdateDTO':
        """Safely construct DTO from request parameters.
        
        Only whitelisted fields are extracted; all others are ignored.
        This prevents mass assignment of sensitive fields like 'role' or 'is_admin'.
        """
        filtered = {
            key: value
            for key, value in params.items()
            if key in USER_PROFILE_UPDATE_ALLOWED_FIELDS
        }
        return cls(**filtered)

    def to_update_dict(self) -> dict:
        """Convert to dict for model update, excluding None values."""
        return {
            key: value
            for key, value in self.__dict__.items()
            if value is not None
        }