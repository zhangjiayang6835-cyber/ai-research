from dataclasses import dataclass, field
from typing import Optional


@dataclass
class UserProfileUpdateDTO:
    """
    Data Transfer Object for user profile updates.
    Explicitly defines which fields can be updated by the user.
    """
    username: Optional[str] = None
    email: Optional[str] = None
    display_name: Optional[str] = None
    bio: Optional[str] = None
    avatar_url: Optional[str] = None
    phone: Optional[str] = None
    location: Optional[str] = None
    website: Optional[str] = None
    timezone: Optional[str] = None
    language: Optional[str] = None
    notification_preferences: Optional[dict] = None
    
    def to_filtered_dict(self) -> dict:
        """Convert DTO to dict, excluding None values."""
        return {k: v for k, v in self.__dict__.items() if v is not None}


@app.route('/api/user/profile', methods=['PUT'])
@require_auth
def update_profile(current_user):
    """
    Update user profile with whitelist-based parameter binding.
    Uses DTO pattern to prevent mass assignment of sensitive fields.
    """
    raw_data = request.get_json()
    
    # Option 1: DTO-based filtering
    dto = UserProfileUpdateDTO(
        username=raw_data.get('username'),
        email=raw_data.get('email'),
        display_name=raw_data.get('display_name'),
        bio=raw_data.get('bio'),
        avatar_url=raw_data.get('avatar_url'),
        phone=raw_data.get('phone'),
        location=raw_data.get('location'),
        website=raw_data.get('website'),
        timezone=raw_data.get('timezone'),
        language=raw_data.get('language'),
        notification_preferences=raw_data.get('notification_preferences'),
    )
    
    # Only pass explicitly allowed fields to the model
    filtered_data = dto.to_filtered_dict()
    current_user.safe_update(filtered_data)
    
    return jsonify({'status': 'ok', 'updated_fields': list(filtered_data.keys())})