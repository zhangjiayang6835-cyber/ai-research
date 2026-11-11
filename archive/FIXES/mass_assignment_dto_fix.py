"""
Mass Assignment / Privilege Escalation Fix
Bounty #785 ($120)
=========================================
Vulnerability: User.update(params) directly binds all request parameters
to the model, allowing attackers to set role=admin or is_admin=true.

Fix: Use DTO (Data Transfer Object) pattern with whitelist-based field
filtering. Only explicitly allowed fields can be updated.
"""

import dataclasses
from typing import Any, Dict, Optional


@dataclasses.dataclass
class UserProfileUpdateDTO:
    """DTO for user profile updates — only these fields are allowed."""
    display_name: Optional[str] = None
    bio: Optional[str] = None
    avatar_url: Optional[str] = None
    email: Optional[str] = None
    phone: Optional[str] = None
    notification_preferences: Optional[Dict[str, bool]] = None

    @classmethod
    def from_request(cls, data: Dict[str, Any]) -> "UserProfileUpdateDTO":
        """Extract only whitelisted fields from raw request data."""
        allowed_fields = {
            "display_name", "bio", "avatar_url",
            "email", "phone", "notification_preferences",
        }
        safe_data = {}
        for key in allowed_fields:
            if key in data:
                safe_data[key] = data[key]

        # Remove sensitive fields that should never be mass-assigned
        blocked_fields = {"role", "is_admin", "permissions", "balance",
                          "password_hash", "mfa_secret", "api_key"}
        for key in blocked_fields:
            safe_data.pop(key, None)

        return cls(**safe_data)


class UserProfileService:
    """Service layer enforcing DTO-based updates."""

    def __init__(self, user_repository):
        self._repo = user_repository

    def update_profile(self, user_id: int, raw_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Update user profile using DTO pattern.
        Only whitelisted fields from UserProfileUpdateDTO are applied.
        """
        dto = UserProfileUpdateDTO.from_request(raw_data)
        update_data = dataclasses.asdict(dto)
        # Remove None values (fields not provided in request)
        update_data = {k: v for k, v in update_data.items() if v is not None}

        if not update_data:
            return {"status": "no_changes", "user_id": user_id}

        # Apply only the filtered update
        updated_user = self._repo.update(user_id, update_data)

        return {
            "status": "updated",
            "user_id": user_id,
            "updated_fields": list(update_data.keys()),
        }


# ========== Usage Example ==========
if __name__ == "__main__":
    # Simulate an attacker trying to escalate privileges
    malicious_request = {
        "display_name": "John Doe",
        "bio": "Software developer",
        "role": "admin",          # ← Mass assignment attempt
        "is_admin": True,          # ← Mass assignment attempt
        "permissions": ["*"],      # ← Mass assignment attempt
    }

    # With DTO pattern, only safe fields are extracted
    dto = UserProfileUpdateDTO.from_request(malicious_request)
    safe_data = dataclasses.asdict(dto)
    safe_data = {k: v for k, v in safe_data.items() if v is not None}

    print("Malicious request:", malicious_request)
    print("Safe update data:", safe_data)
    # Output: {'display_name': 'John Doe', 'bio': 'Software developer'}
    # The role, is_admin, permissions fields are all blocked.
