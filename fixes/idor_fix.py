"""
Fix for Issue #12 — IDOR in User Profile API
=============================================

Vulnerability
-------------
User profile endpoint trusts the ``user_id`` parameter without
verifying ownership, allowing any authenticated user to access
another user's private data.

Fix Strategy
------------
1. Require authentication on every request.
2. Verify the requesting user owns the requested profile (or has
   admin privileges).
3. Return 404 instead of 403 to avoid user enumeration.
"""

from __future__ import annotations

from typing import Any, Dict, Optional


def get_user_profile(user_id: str, current_user: Dict[str, Any], db: Any) -> Optional[Dict]:
    """
    Retrieve a user profile with ownership verification.
    
    Args:
        user_id: The ID of the profile to retrieve.
        current_user: Dict with at least 'id' and 'role' keys.
        db: Database connection object.
    
    Returns:
        User profile dict, or None if not found/access denied.
    """
    # Require authentication
    if not current_user or "id" not in current_user:
        return None

    # Allow admins to view any profile
    if current_user.get("role") == "admin":
        return db.query("SELECT * FROM users WHERE id = ?", (user_id,)).first()

    # Regular users can only view their own profile
    if current_user["id"] != user_id:
        return None  # Return None, not 403, to avoid enumeration

    return db.query("SELECT * FROM users WHERE id = ?", (user_id,)).first()
