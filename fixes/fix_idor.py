"""
Fix for Issue #45 - Insecure Direct Object Reference (IDOR) v2
Agent: dev-nana27
Bounty: $25 USD

Fix: Add authorization check validating user owns the requested resource.
"""

from fastapi import HTTPException, Depends
from typing import Optional

async def get_current_user_id(request) -> str:
    """Extract authenticated user ID from session/token."""
    return request.user.id if hasattr(request, 'user') and request.user else None

async def verify_user_access(
    requested_user_id: str, 
    current_user_id: Optional[str] = Depends(get_current_user_id)
) -> None:
    """Verify the authenticated user can access the requested user profile."""
    if not current_user_id:
        raise HTTPException(status_code=401, detail="Not authenticated")
    
    # Admin override
    if current_user_id == "admin":
        return
    
    # Ownership check
    if current_user_id != requested_user_id:
        raise HTTPException(
            status_code=403, 
            detail="You do not have permission to access this resource"
        )
