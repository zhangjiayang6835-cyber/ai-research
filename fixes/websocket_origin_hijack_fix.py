#!/usr/bin/env python3
"""
Fix for WebSocket Cross-Origin Hijacking and Session Prediction.
Apply this patch to validate WebSocket Origins and strengthen session tokens.
"""
import os
import secrets
import hmac
from typing import Optional, List

def validate_websocket_origin(origin: Optional[str], allowed_origins: Optional[List[str]] = None) -> None:
    """Validate Origin header for WebSocket handshake."""
    if not origin:
        raise ValueError("Missing Origin header")
    
    if allowed_origins is None:
        allowed_origins = os.environ.get('ALLOWED_ORIGINS', '').split(',')
    
    # Remove trailing slash for normalization
    origin = origin.rstrip('/')
    
    if origin not in allowed_origins:
        raise ValueError(f"Origin '{origin}' not allowed")


def generate_secure_session_token(length: int = 32) -> str:
    """Generate a cryptographically secure session token using secrets module."""
    return secrets.token_urlsafe(length)


def verify_session_token(token: str, stored_token: str) -> bool:
    """Constant-time comparison to prevent timing attacks."""
    return hmac.compare_digest(token, stored_token)


# Example usage in WebSocket handler:
# from fixes.websocket_origin_hijack_fix import validate_websocket_origin, generate_secure_session_token
# 
# async def on_websocket_connect(request):
#     try:
#         validate_websocket_origin(request.headers.get('Origin'))
#     except ValueError as e:
#         return HTTPResponse(status=403, body=str(e))
