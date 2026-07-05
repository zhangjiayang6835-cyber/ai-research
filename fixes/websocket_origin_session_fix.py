"""Defense-in-depth fix for issue #344: CSWSH plus session prediction.

Cross-Site WebSocket Hijacking happens when a browser can open an authenticated
WebSocket from an attacker origin and cookies are accepted without an Origin
check. If the WebSocket session identifier is also predictable, the attacker can
reuse or guess a live channel.

This module is framework-neutral. Call ``WebSocketHandshakeGuard.validate`` in
your WebSocket upgrade handler before accepting the socket.
"""

from __future__ import annotations

import hmac
import secrets
from dataclasses import dataclass
from typing import Mapping
from urllib.parse import urlsplit


class WebSocketSecurityError(ValueError):
    """Raised when a WebSocket handshake fails security validation."""


def _canonical_origin(origin: str) -> str:
    parsed = urlsplit(origin)
    if parsed.scheme not in {"https", "wss"} or not parsed.netloc:
        raise WebSocketSecurityError("Invalid WebSocket origin")
    host = parsed.hostname
    if not host:
        raise WebSocketSecurityError("Invalid WebSocket origin host")
    port = f":{parsed.port}" if parsed.port else ""
    return f"{parsed.scheme}://{host.lower()}{port}"


def generate_ws_session_id() -> str:
    """Return a high-entropy WebSocket session identifier."""

    return secrets.token_urlsafe(32)


@dataclass(frozen=True)
class WebSocketSession:
    """Accepted WebSocket session metadata."""

    session_id: str
    user_id: str
    origin: str
    csrf_token: str


@dataclass(frozen=True)
class WebSocketHandshakeGuard:
    """Validate origin, CSRF binding, and session entropy before upgrade."""

    allowed_origins: frozenset[str]
    require_csrf: bool = True

    def __post_init__(self) -> None:
        if not self.allowed_origins:
            raise WebSocketSecurityError("At least one allowed origin is required")
        normalized = frozenset(_canonical_origin(origin) for origin in self.allowed_origins)
        object.__setattr__(self, "allowed_origins", normalized)

    def validate_origin(self, origin: str | None) -> str:
        if not origin:
            raise WebSocketSecurityError("Missing Origin header")
        normalized = _canonical_origin(origin)
        if normalized not in self.allowed_origins:
            raise WebSocketSecurityError("Origin is not allowed")
        return normalized

    def validate_csrf(self, expected_token: str | None, submitted_token: str | None) -> None:
        if not self.require_csrf:
            return
        if not expected_token or not submitted_token:
            raise WebSocketSecurityError("Missing WebSocket CSRF token")
        if not hmac.compare_digest(expected_token, submitted_token):
            raise WebSocketSecurityError("Invalid WebSocket CSRF token")

    def validate(
        self,
        headers: Mapping[str, str],
        session: Mapping[str, str],
        *,
        session_id_factory=generate_ws_session_id,
    ) -> WebSocketSession:
        """Validate a WebSocket handshake and return fresh channel metadata."""

        origin = self.validate_origin(headers.get("Origin") or headers.get("origin"))
        self.validate_csrf(
            session.get("csrf_token"),
            headers.get("Sec-WebSocket-Protocol") or headers.get("X-CSRF-Token"),
        )

        user_id = session.get("user_id")
        if not user_id:
            raise WebSocketSecurityError("Missing authenticated user")

        return WebSocketSession(
            session_id=session_id_factory(),
            user_id=user_id,
            origin=origin,
            csrf_token=session.get("csrf_token", ""),
        )


def websocket_cookie_headers(session_id: str, *, https_only: bool = True) -> dict[str, str]:
    """Return cookie headers that keep the WebSocket session browser-bound."""

    if not session_id:
        raise WebSocketSecurityError("Missing WebSocket session id")
    parts = [f"ws_session={session_id}", "Path=/", "HttpOnly", "SameSite=Strict"]
    if https_only:
        parts.append("Secure")
    return {"Set-Cookie": "; ".join(parts)}


__all__ = [
    "WebSocketHandshakeGuard",
    "WebSocketSecurityError",
    "WebSocketSession",
    "generate_ws_session_id",
    "websocket_cookie_headers",
]
