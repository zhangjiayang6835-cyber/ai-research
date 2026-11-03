"""
Fix for Issue #1491: Session Fixation + Session ID in URL

VULNERABILITY
-------------
1. Session Fixation: Applications that do not regenerate session IDs upon successful
   authentication allow an attacker to fixate a session ID (e.g., via a pre-created session
   or URL parameter) and trick a victim into logging into it, giving the attacker full
   access to the victim's authenticated session.
2. Session ID in URL: Accepting session IDs via URL query parameters (e.g., `?sid=...`)
   leaks session identifiers through browser history, Referer headers, and server logs.
3. Insecure Cookie Flags: Session cookies lacking HttpOnly, Secure, or SameSite=Strict
   attributes are vulnerable to XSS exfiltration, CSRF, and MITM interception.

FIX
---
- Reject session IDs passed via URL query parameters.
- Regenerate session IDs upon user login/authentication.
- Enforce HttpOnly, Secure, and SameSite=Strict cookies.
- Implement robust session validation using cryptographically secure tokens.
"""

from __future__ import annotations

import secrets
import threading
import time
from dataclasses import dataclass
from typing import Dict, Optional


def generate_session_id() -> str:
    """Return a strong, cryptographically secure session ID."""
    return secrets.token_urlsafe(32)


@dataclass
class SessionRecord:
    user_id: object
    expires_at: float


class SessionManager:
    """Session manager preventing session fixation and URL session ID leakage."""

    def __init__(self, ttl_seconds: int = 3600) -> None:
        self._ttl = ttl_seconds
        self._store: Dict[str, SessionRecord] = {}
        self._lock = threading.Lock()

    def create_session(self, user_id: object) -> str:
        """Create a new session for an unauthenticated or authenticated user."""
        sid = generate_session_id()
        with self._lock:
            self._store[sid] = SessionRecord(
                user_id=user_id,
                expires_at=time.time() + self._ttl,
            )
        return sid

    def validate_session(self, session_id: Optional[str], query_params: Optional[dict] = None) -> Optional[object]:
        """Validate session ID, strictly rejecting URL-based session IDs."""
        if query_params and ("sid" in query_params or "session_id" in query_params or "token" in query_params):
            return None  # Reject URL-based session IDs

        if not session_id or not isinstance(session_id, str):
            return None

        with self._lock:
            rec = self._store.get(session_id)
            if not rec:
                return None
            if rec.expires_at < time.time():
                self._store.pop(session_id, None)
                return None
            return rec.user_id

    def login(self, old_session_id: Optional[str], user_id: object) -> str:
        """Regenerate session on login to prevent session fixation."""
        with self._lock:
            if old_session_id:
                self._store.pop(old_session_id, None)
        return self.create_session(user_id=user_id)

    def get_cookie_attrs(self) -> dict[str, bool | str]:
        """Return secure cookie attributes."""
        return {
            "httponly": True,
            "secure": True,
            "samesite": "Strict",
            "path": "/",
        }
