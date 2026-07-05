"""Defense-in-depth fix for issue #339: cache deception + session fixation.

Two flaws often chain together:

* a private route such as ``/account/profile.css`` returns authenticated HTML
  but a CDN caches it because the URL looks static; and
* login keeps an attacker-supplied session identifier alive after privilege
  changes.

This module is framework-neutral. Use ``WebCacheDeceptionGuard`` before sending
responses and ``SessionFixationGuard.rotate_on_authentication`` whenever a user
authenticates or changes privilege.
"""

from __future__ import annotations

import secrets
from collections.abc import Callable, MutableMapping
from dataclasses import dataclass, field
from pathlib import PurePosixPath
from typing import Any
from urllib.parse import unquote, urlsplit


class WebCacheSessionFixationError(ValueError):
    """Raised when a request cannot be safely served or cached."""


_DEFAULT_STATIC_EXTENSIONS = frozenset(
    {
        ".avif",
        ".css",
        ".gif",
        ".ico",
        ".jpeg",
        ".jpg",
        ".js",
        ".png",
        ".svg",
        ".txt",
        ".webp",
        ".woff",
        ".woff2",
    }
)
_DEFAULT_PRIVATE_PREFIXES = (
    "/account",
    "/admin",
    "/api",
    "/billing",
    "/checkout",
    "/dashboard",
    "/me",
    "/orders",
    "/profile",
    "/settings",
    "/users",
)


def _normalize_path(raw_path: str) -> str:
    path = urlsplit(raw_path).path or "/"
    decoded = unquote(path).replace("\\", "/")
    normalized = PurePosixPath("/" + decoded.lstrip("/")).as_posix()
    if "\x00" in normalized or "/../" in f"{normalized}/":
        raise WebCacheSessionFixationError("Invalid request path")
    return normalized


@dataclass(frozen=True)
class CacheDecision:
    """Cache policy returned by ``WebCacheDeceptionGuard``."""

    cacheable: bool
    reason: str
    headers: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class WebCacheDeceptionGuard:
    """Reject private fake-static URLs and emit safe cache headers."""

    private_prefixes: tuple[str, ...] = _DEFAULT_PRIVATE_PREFIXES
    static_extensions: frozenset[str] = _DEFAULT_STATIC_EXTENSIONS

    def looks_like_static_asset(self, path: str) -> bool:
        suffix = PurePosixPath(_normalize_path(path)).suffix.lower()
        return suffix in self.static_extensions

    def is_private_route(self, path: str) -> bool:
        normalized = _normalize_path(path)
        return any(
            normalized == prefix or normalized.startswith(f"{prefix}/")
            for prefix in self.private_prefixes
        )

    def validate_route(self, path: str, *, authenticated: bool) -> None:
        """Block private routes disguised as static assets.

        A request like ``/account/profile.css`` should not be routed to the
        authenticated account handler. It should be a 404/400 before a CDN sees
        a cacheable-looking URL paired with private content.
        """

        if authenticated and self.is_private_route(path) and self.looks_like_static_asset(path):
            raise WebCacheSessionFixationError("Private route uses static-looking path")

    def cache_decision(
        self,
        path: str,
        *,
        authenticated: bool,
        contains_private_data: bool,
    ) -> CacheDecision:
        """Return conservative cache headers for a response."""

        self.validate_route(path, authenticated=authenticated)

        if authenticated or contains_private_data or self.is_private_route(path):
            return CacheDecision(
                cacheable=False,
                reason="private response",
                headers={
                    "Cache-Control": "no-store, private",
                    "Pragma": "no-cache",
                    "Vary": "Authorization, Cookie",
                    "X-Content-Type-Options": "nosniff",
                },
            )

        if self.looks_like_static_asset(path):
            return CacheDecision(
                cacheable=True,
                reason="public static asset",
                headers={
                    "Cache-Control": "public, max-age=31536000, immutable",
                    "X-Content-Type-Options": "nosniff",
                },
            )

        return CacheDecision(
            cacheable=False,
            reason="dynamic public response",
            headers={
                "Cache-Control": "no-store",
                "X-Content-Type-Options": "nosniff",
            },
        )


def generate_session_id() -> str:
    """Return a high-entropy, URL-safe session identifier."""

    return secrets.token_urlsafe(32)


@dataclass
class SessionFixationGuard:
    """Rotate session identifiers on authentication and privilege changes."""

    token_factory: Callable[[], str] = generate_session_id

    def rotate_on_authentication(
        self,
        session: MutableMapping[str, Any],
        *,
        user_id: str,
        preserve_keys: tuple[str, ...] = ("csrf_token",),
    ) -> str:
        """Clear attacker-controlled pre-login state and issue a new ID."""

        preserved = {key: session[key] for key in preserve_keys if key in session}
        new_session_id = self.token_factory()

        session.clear()
        session.update(preserved)
        session["session_id"] = new_session_id
        session["user_id"] = user_id
        session["authenticated"] = True
        session["session_rotated"] = True

        return new_session_id


def secure_session_cookie_headers(session_id: str, *, https_only: bool = True) -> dict[str, str]:
    """Return a Set-Cookie header for the rotated session identifier."""

    if not session_id:
        raise WebCacheSessionFixationError("Missing session id")

    parts = [f"session_id={session_id}", "Path=/", "HttpOnly", "SameSite=Lax"]
    if https_only:
        parts.append("Secure")
    return {"Set-Cookie": "; ".join(parts)}


__all__ = [
    "CacheDecision",
    "SessionFixationGuard",
    "WebCacheDeceptionGuard",
    "WebCacheSessionFixationError",
    "generate_session_id",
    "secure_session_cookie_headers",
]
