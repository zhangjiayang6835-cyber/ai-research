from flask import request, jsonify, g
from src.models.user import User, UserProfileUpdateDTO, SENSITIVE_FIELDS


@app.route('/api/user/profile', methods=['PUT', 'PATCH'])
@require_auth
def update_user_profile():
    """Update the authenticated user's profile.
    
    Uses DTO pattern with strict whitelist to prevent mass assignment
    of sensitive fields (role, is_admin, permissions, etc.).
    """
    current_user = g.current_user
    params = request.get_json() or {}
    
    # Security check: reject requests containing sensitive fields
    sensitive_in_request = set(params.keys()) & SENSITIVE_FIELDS
    if sensitive_in_request:
        return jsonify({
            'error': 'Invalid request',
            'message': 'Request contains forbidden fields.',
            'forbidden_fields': list(sensitive_in_request),
        }), 400
    
    # Build DTO from whitelisted fields only
    profile_dto = UserProfileUpdateDTO.from_request(params)
    update_data = profile_dto.to_update_dict()
    
    if not update_data:
        return jsonify({
            'error': 'No valid fields to update',
            'allowed_fields': list(USER_PROFILE_UPDATE_ALLOWED_FIELDS),
        }), 400
    
    # Apply only whitelisted updates
    for field, value in update_data.items():
        setattr(current_user, field, value)
    
    current_user.save()
    
    return jsonify({
        'message': 'Profile updated successfully',
        'user': current_user.to_safe_dict(),
    }), 200


# Alternative: if using an ORM with update() method
def safe_user_update(user, params: dict) -> None:
    """Safe wrapper for user updates - only allows whitelisted fields."""
    dto = UserProfileUpdateDTO.from_request(params)
    user.update(**dto.to_update_dict())  # Only whitelisted fields passed