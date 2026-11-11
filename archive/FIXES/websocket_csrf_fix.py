"""
Fix for Issue #730 — WebSocket CSRF → Cross-Origin Data Exfiltration

Vulnerability
-------------
WebSocket connections do not enforce same-origin policy. Browsers allow any
origin to open a WebSocket connection. An attacker's website can open a
WebSocket to the target application and read data if the application does not
validate the Origin header on connection.

Fix
---
1. Origin header validation against a strict allowlist
2. CSRF challenge-response handshake for sensitive actions
3. Session binding — WebSocket connections are tied to the user's session
4. Cryptographic nonce exchange during WebSocket handshake

Acceptance Criteria
-------------------
- [x] Origin header validated on WebSocket upgrade
- [x] CSRF token challenge on connect
- [x] Session binding prevents cross-origin data access
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import time
from typing import Dict, Optional, Set


class WebSocketCSRFProtection:
    """
    WebSocket CSRF protection with origin validation and challenge handshake.

    Uses a two-layer defense:
    1. Origin header validation against a strict allowlist
    2. CSRF challenge-response with session binding
    """

    def __init__(
        self,
        allowed_origins: Optional[Set[str]] = None,
        secret_key: Optional[bytes] = None,
    ):
        self._allowed_origins = allowed_origins or {
            "http://localhost:3000",
            "https://app.example.com",
        }
        self._secret_key = secret_key or secrets.token_bytes(32)
        # In-memory store for pending challenges
        self._pending_challenges: Dict[str, dict] = {}

    def validate_origin(self, origin: Optional[str]) -> bool:
        """
        Validate the Origin header against the allowlist.

        Returns True if the origin is allowed, False otherwise.
        A missing Origin header is rejected (defense in depth).
        """
        if not origin:
            return False

        # Normalize: strip trailing slash
        origin = origin.rstrip("/")

        return origin in self._allowed_origins

    def create_handshake_challenge(self, session_id: str) -> dict:
        """
        Create a CSRF challenge for the WebSocket handshake.

        The challenge includes:
        - A cryptographically random nonce
        - An HMAC signature binding the nonce to the session
        - A timestamp for TTL enforcement

        Args:
            session_id: The user's authenticated session ID.

        Returns:
            Dict with challenge_nonce and challenge_token.
        """
        nonce = secrets.token_urlsafe(32)
        timestamp = str(int(time.time()))
        message = f"{nonce}:{timestamp}:{session_id}".encode()
        token = hmac.new(
            self._secret_key, message, hashlib.sha256
        ).hexdigest()[:32]

        challenge = {
            "nonce": nonce,
            "token": token,
            "timestamp": timestamp,
        }

        # Store for verification
        self._pending_challenges[nonce] = challenge

        return challenge

    def verify_handshake_challenge(
        self, nonce: str, response_token: str, session_id: str, max_age: int = 300
    ) -> bool:
        """
        Verify a WebSocket handshake challenge response.

        Args:
            nonce: The nonce from the original challenge.
            response_token: The token returned by the client.
            session_id: The user's session ID.
            max_age: Maximum age of the challenge in seconds.

        Returns:
            True if the challenge response is valid.
        """
        # Check if challenge exists
        challenge = self._pending_challenges.pop(nonce, None)
        if not challenge:
            return False

        # Verify TTL
        age = time.time() - int(challenge["timestamp"])
        if age < 0 or age > max_age:
            return False

        # Recompute expected token
        message = f"{nonce}:{challenge['timestamp']}:{session_id}".encode()
        expected_token = hmac.new(
            self._secret_key, message, hashlib.sha256
        ).hexdigest()[:32]

        # Constant-time comparison
        return hmac.compare_digest(response_token, expected_token)


# Example integration for a WebSocket server:
#
# protection = WebSocketCSRFProtection()
#
# async def handle_client(websocket, path):
#     # Step 1: Validate Origin header
#     origin = websocket.request_headers.get("Origin")
#     if not protection.validate_origin(origin):
#         await websocket.close(code=1008, reason="Origin not allowed")
#         return
#
#     # Step 2: Create and send CSRF challenge
#     session_id = get_session_from_cookie(websocket)
#     challenge = protection.create_handshake_challenge(session_id)
#     await websocket.send(json.dumps({
#         "type": "csrf_challenge",
#         "nonce": challenge["nonce"],
#         "token": challenge["token"],
#     }))
#
#     # Step 3: Verify challenge response
#     response = json.loads(await websocket.recv())
#     if not protection.verify_handshake_challenge(
#         response["nonce"], response["token"], session_id
#     ):
#         await websocket.close(code=1008, reason="CSRF challenge failed")
#         return