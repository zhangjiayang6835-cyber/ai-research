"""
Fix for Issue #1350 — WebSocket Hijacking via Missing Cookie Validation
=======================================================================

Vulnerability
-------------
The WebSocket upgrade validates only the ``Origin`` header, then trusts the
connection for its whole lifetime. Authentication rides on the ambient session
**cookie**, which the browser attaches automatically to the cross-site upgrade
request. This is Cross-Site WebSocket Hijacking (CSWSH):

- ``Origin`` is not a real authentication signal — non-browser clients set it
  freely, and any allowlist slip (subdomain, ``null``, regex) defeats it.
- Because the cookie is ambient, a victim merely visiting the attacker's page
  opens an authenticated socket *as the victim*.
- After the handshake, individual messages are never re-authenticated, so a
  hijacked/borrowed connection can impersonate the user indefinitely.

Fix (per the issue's acceptance criteria)
-----------------------------------------
1. **Verify a Bearer token on connection.** Authentication uses a non-ambient
   signed token supplied explicitly (``Authorization: Bearer ...`` /
   subprotocol), not the cookie. ``Origin`` is still checked as defence in
   depth but is never the sole control.
2. **Verify the token on every message.** Each message must carry a valid,
   unexpired token; expired or revoked tokens are rejected mid-stream.
3. **Bind the token to the user session.** The token embeds ``sub`` (user) and
   ``sid`` (session); a message whose token does not match the connection's
   bound user/session is rejected, so a hijacked transport cannot speak for
   another user.

This is a self-contained reference implementation (HMAC-signed tokens) that a
real server (websockets/Starlette/etc.) can wire into its connect/receive hooks.

Acceptance Criteria
-------------------
- [x] Bearer token verified at connection time
- [x] Token validity verified on every message
- [x] Token bound to user session (sub + sid)
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
from dataclasses import dataclass
from typing import Any, Callable, Iterable, Mapping


class WebSocketAuthError(Exception):
    """Raised when a WebSocket connection or message fails authentication."""


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(segment: str) -> bytes:
    padding = "=" * (-len(segment) % 4)
    try:
        return base64.urlsafe_b64decode((segment + padding).encode("ascii"))
    except (ValueError, TypeError) as exc:
        raise WebSocketAuthError("invalid token encoding") from exc


@dataclass(frozen=True)
class Principal:
    """The authenticated identity bound to a WebSocket connection."""

    user_id: str
    session_id: str


class SessionTokenAuthenticator:
    """Issues and verifies HMAC-signed, session-bound Bearer tokens.

    Tokens are *not* cookies: they must be presented explicitly, so they are not
    attached automatically on a cross-site request — which is what defeats CSWSH.
    """

    def __init__(
        self,
        secret: bytes,
        *,
        ttl_seconds: int = 900,
        now: Callable[[], float] | None = None,
    ) -> None:
        if not secret:
            raise ValueError("secret must be non-empty")
        self._secret = secret
        self._ttl = int(ttl_seconds)
        self._now = now or time.time
        # Active sessions -> user. Revoking removes the entry (logout, rotation).
        self._sessions: dict[str, str] = {}

    # -- session lifecycle -------------------------------------------------

    def start_session(self, user_id: str, session_id: str) -> str:
        """Register a session and return a signed Bearer token for it."""
        if not user_id or not session_id:
            raise ValueError("user_id and session_id are required")
        self._sessions[session_id] = user_id
        return self._sign(user_id, session_id)

    def revoke_session(self, session_id: str) -> None:
        self._sessions.pop(session_id, None)

    def refresh_token(self, session_id: str) -> str:
        user_id = self._sessions.get(session_id)
        if user_id is None:
            raise WebSocketAuthError("cannot refresh an inactive session")
        return self._sign(user_id, session_id)

    # -- token verification ------------------------------------------------

    def verify(self, token: str) -> Principal:
        """Validate signature, expiry, and active-session binding."""
        if not isinstance(token, str) or token.count(".") != 2:
            raise WebSocketAuthError("malformed token")
        header_b64, payload_b64, sig_b64 = token.split(".")

        expected = self._mac(f"{header_b64}.{payload_b64}")
        if not hmac.compare_digest(_b64url_decode(sig_b64), expected):
            raise WebSocketAuthError("invalid token signature")

        try:
            payload = json.loads(_b64url_decode(payload_b64))
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise WebSocketAuthError("invalid token payload") from exc
        if not isinstance(payload, dict):
            raise WebSocketAuthError("invalid token payload")

        exp = payload.get("exp")
        if not isinstance(exp, (int, float)) or exp <= self._now():
            raise WebSocketAuthError("token expired")

        user_id = payload.get("sub")
        session_id = payload.get("sid")
        if not isinstance(user_id, str) or not isinstance(session_id, str):
            raise WebSocketAuthError("token missing sub/sid")

        # Session binding: reject tokens for logged-out / rotated sessions, or
        # whose embedded user no longer matches the live session.
        if self._sessions.get(session_id) != user_id:
            raise WebSocketAuthError("token not bound to an active session")

        return Principal(user_id=user_id, session_id=session_id)

    # -- internals ---------------------------------------------------------

    def _sign(self, user_id: str, session_id: str) -> str:
        now = int(self._now())
        payload = {
            "sub": user_id,
            "sid": session_id,
            "iat": now,
            "exp": now + self._ttl,
        }
        header_b64 = _b64url_encode(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
        payload_b64 = _b64url_encode(json.dumps(payload, sort_keys=True).encode())
        sig = self._mac(f"{header_b64}.{payload_b64}")
        return f"{header_b64}.{payload_b64}.{_b64url_encode(sig)}"

    def _mac(self, signing_input: str) -> bytes:
        return hmac.new(self._secret, signing_input.encode("ascii"), hashlib.sha256).digest()


def _bearer_token(auth_header: str | None) -> str:
    if not auth_header or not isinstance(auth_header, str):
        raise WebSocketAuthError("missing Authorization header")
    scheme, _, value = auth_header.partition(" ")
    if scheme.lower() != "bearer" or not value.strip():
        raise WebSocketAuthError("expected 'Authorization: Bearer <token>'")
    return value.strip()


class SecureWebSocketServer:
    """Authenticates the WebSocket handshake and every subsequent message."""

    def __init__(
        self,
        authenticator: SessionTokenAuthenticator,
        allowed_origins: Iterable[str],
    ) -> None:
        self._auth = authenticator
        self._allowed_origins = frozenset(allowed_origins)

    def is_allowed_origin(self, origin: str | None) -> bool:
        # Exact-match allowlist; no cookie is trusted for auth regardless.
        return isinstance(origin, str) and origin in self._allowed_origins

    def authenticate_connection(
        self,
        *,
        origin: str | None,
        authorization: str | None,
    ) -> Principal:
        """Criterion 1: verify Origin (defence in depth) + Bearer token."""
        if not self.is_allowed_origin(origin):
            raise WebSocketAuthError("origin not allowed")
        token = _bearer_token(authorization)
        return self._auth.verify(token)

    def authenticate_message(
        self,
        connection: Principal,
        message: Mapping[str, Any],
    ) -> Any:
        """Criteria 2 & 3: verify the per-message token and session binding.

        ``message`` must be a mapping carrying a ``token`` field. Returns the
        message ``data`` on success; raises ``WebSocketAuthError`` otherwise.
        """
        if not isinstance(message, Mapping):
            raise WebSocketAuthError("message must be a structured object with a token")
        token = message.get("token")
        if not isinstance(token, str):
            raise WebSocketAuthError("message missing authentication token")

        principal = self._auth.verify(token)  # re-checks signature + expiry + session
        # Binding: the message's identity must match the connection's identity.
        if principal != connection:
            raise WebSocketAuthError("message token does not match the connection's session")
        return message.get("data")


__all__ = [
    "WebSocketAuthError",
    "Principal",
    "SessionTokenAuthenticator",
    "SecureWebSocketServer",
]
