"""
Fix for Issue #1336 — WebSocket CSRF → Cross-Origin Data Exfiltration
======================================================================

Vulnerability
-------------
The WebSocket server validates the Origin header at connection time but
does NOT:
- Verify a CSRF token bound to the user's HTTP session
- Authenticate individual WebSocket messages
- Reject unauthenticated data access requests

An attacker's page can open a cross-origin WebSocket (if the origin
check passes or the attacker controls an allowed subdomain) and
exfiltrate sensitive data.

Fix Strategy
------------
1. Strict Origin validation against an exact domain allow-list.
2. Require a CSRF token (proof-of-possession) during WebSocket upgrade
   via the Sec-WebSocket-Protocol header.
3. Bind each WebSocket message to the user's session via HMAC tokens.
4. Require explicit data access permission per-message.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import time
from typing import Any, Dict, Optional, Set


# ── Configuration ─────────────────────────────────────────────────────

_DEFAULT_ALLOWED_ORIGINS: Set[str] = {
    "http://localhost:3000",
    "https://app.example.com",
}

SESSION_SECRET = os.environ.get("WS_SESSION_SECRET", secrets.token_hex(32))


class WebSocketCSRFError(Exception):
    """Raised when WebSocket CSRF validation fails."""


class OriginValidationError(Exception):
    """Raised when origin validation fails."""


class MessageAuthenticationError(Exception):
    """Raised when WebSocket message authentication fails."""


# ── Origin Validation ────────────────────────────────────────────────

def validate_origin(
    origin: Optional[str],
    allowed_origins: Optional[Set[str]] = None,
) -> str:
    """Strictly validate an Origin header against the allow-list.

    Args:
        origin: The Origin header value from the WebSocket upgrade.
        allowed_origins: Set of allowed origins.

    Returns:
        The normalized origin if valid.

    Raises:
        OriginValidationError: If origin is missing or not allowed.
    """
    if allowed_origins is None:
        allowed_origins = _DEFAULT_ALLOWED_ORIGINS

    if not origin:
        raise OriginValidationError("Origin header is missing")

    # Normalize: strip trailing slash
    origin = origin.rstrip("/")

    # Exact match against allow-list
    if origin not in allowed_origins:
        raise OriginValidationError(f"Origin not allowed: {origin}")

    return origin


# ── CSRF Token for WebSocket Upgrade ─────────────────────────────────

def generate_ws_csrf_token(session_id: str) -> str:
    """Generate a CSRF token bound to a WebSocket session.

    The token is an HMAC of the session ID that proves the
    WebSocket upgrade requestor holds the HTTP session.
    """
    return hmac.new(
        SESSION_SECRET.encode(),
        f"ws:{session_id}".encode(),
        hashlib.sha256,
    ).hexdigest()[:32]


def validate_ws_csrf_token(
    session_id: str,
    token: str,
) -> bool:
    """Validate a WebSocket CSRF token.

    Args:
        session_id: The HTTP session ID.
        token: The CSRF token from the WebSocket upgrade.

    Returns:
        True if the token is valid.
    """
    expected = generate_ws_csrf_token(session_id)
    return hmac.compare_digest(expected, token)


# ── Session-Bound Message Authentication ─────────────────────────────

def generate_message_token(
    session_id: str,
    action: str,
    timestamp: Optional[int] = None,
) -> str:
    """Generate an HMAC token that binds a message to a session.

    Args:
        session_id: The authenticated session ID.
        action: The WebSocket action being authenticated.
        timestamp: Optional timestamp (defaults to current time).

    Returns:
        An HMAC token string.
    """
    if timestamp is None:
        timestamp = int(time.time())
    message = f"{session_id}:{action}:{timestamp // 30}"
    return hmac.new(
        SESSION_SECRET.encode(),
        message.encode(),
        hashlib.sha256,
    ).hexdigest()[:16]


def verify_message_token(
    session_id: str,
    action: str,
    token: str,
    timestamp: Optional[int] = None,
) -> bool:
    """Verify an HMAC message token.

    Args:
        session_id: The authenticated session ID.
        action: The WebSocket action.
        token: The token to verify.
        timestamp: Optional timestamp (defaults to current time).

    Returns:
        True if the token is valid.
    """
    expected = generate_message_token(session_id, action, timestamp)
    return hmac.compare_digest(expected, token)


# ── Data Access Control ──────────────────────────────────────────────

# Define which data types require authentication and authorization
_SENSITIVE_DATA_TYPES: Set[str] = {
    "sensitive",
    "credentials",
    "personal_info",
    "financial_data",
    "internal_config",
}

_PUBLIC_DATA_TYPES: Set[str] = {
    "public_info",
    "metadata",
    "status",
}


def authorize_data_access(
    session_id: Optional[str],
    data_type: str,
    role: Optional[str] = None,
) -> bool:
    """Check if a session is authorized to access a data type.

    Args:
        session_id: The session ID (None for unauthenticated).
        data_type: The type of data being requested.
        role: Optional user role.

    Returns:
        True if access is permitted.
    """
    # Public data: always accessible
    if data_type in _PUBLIC_DATA_TYPES:
        return True

    # Sensitive data: requires authenticated session
    if data_type in _SENSITIVE_DATA_TYPES:
        if session_id is None:
            return False
        if role and role not in ("admin", "owner"):
            return False
        return True

    # Unknown data types: deny by default
    return False


# ── WebSocket Message Processor ──────────────────────────────────────

class AuthenticatedWebSocketProcessor:
    """Process WebSocket messages with CSRF and session authentication."""

    def __init__(self, allowed_origins: Optional[Set[str]] = None):
        self.allowed_origins = allowed_origins or _DEFAULT_ALLOWED_ORIGINS

    def validate_upgrade(
        self,
        origin: Optional[str],
        session_id: Optional[str],
        csrf_token: Optional[str],
    ) -> None:
        """Validate WebSocket upgrade request.

        Args:
            origin: Origin header value.
            session_id: HTTP session ID.
            csrf_token: CSRF token from Sec-WebSocket-Protocol.

        Raises:
            OriginValidationError: If origin is invalid.
            WebSocketCSRFError: If CSRF token is missing or invalid.
        """
        # Step 1: Validate origin
        validate_origin(origin, self.allowed_origins)

        # Step 2: Validate CSRF token (proof of session ownership)
        if not session_id:
            raise WebSocketCSRFError("No session ID provided")

        if not csrf_token:
            raise WebSocketCSRFError("No CSRF token provided")

        if not validate_ws_csrf_token(session_id, csrf_token):
            raise WebSocketCSRFError("Invalid CSRF token")

    def process_message(
        self,
        session_id: str,
        message: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Process an authenticated WebSocket message.

        Args:
            session_id: The authenticated session ID.
            message: The parsed JSON message from the client.

        Returns:
            A response dict.

        Raises:
            MessageAuthenticationError: If the message token is invalid.
        """
        action = message.get("action", "")
        token = message.get("_token", "")

        # Verify message authentication token
        if not verify_message_token(session_id, action, token):
            raise MessageAuthenticationError("Invalid message token")

        # Check data access authorization
        data_type = message.get("type", "")
        role = message.get("_role")
        if not authorize_data_access(session_id, data_type, role):
            return {"error": "Access denied", "status": "denied"}

        # Process allowed actions
        if action == "ping":
            return {"type": "pong", "status": "ok"}
        elif action == "get_data":
            return {"data": f"Data for {data_type}", "status": "ok"}
        elif action == "get_public_info":
            return {"info": "Public information", "status": "ok"}
        else:
            return {"error": "Unknown action", "status": "error"}
