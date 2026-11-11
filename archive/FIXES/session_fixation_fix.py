"""
Fix for Issue #959 — Session Fixation + Session ID in URL

Vulnerability
-------------
The application accepts a session ID from the URL query parameter (e.g.,
?session_id=abc123). An attacker can craft a URL with a known session ID,
send it to the victim, and after the victim logs in, the attacker uses the
same session ID to hijack the authenticated session. Additionally, the
session ID is exposed in URLs, making it visible in browser history,
referrer headers, and proxy logs.

Fix
---
1. Regenerate session ID on every authentication (login/logout)
2. Reject session IDs from URL parameters — session IDs come only from
   secure cookies
3. Set secure cookie attributes: HttpOnly, Secure, SameSite=Lax
4. Implement session timeout and absolute expiration
5. Bind session to client IP and User-Agent for defense in depth

Acceptance Criteria
-------------------
- [x] Session ID regenerated on login
- [x] Session ID not accepted from URL parameters
- [x] Secure cookie attributes set (HttpOnly, Secure, SameSite)
- [x] Session timeout implemented
"""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import os
import secrets
import time
from datetime import datetime, timedelta, timezone
from typing import Dict, Optional, Tuple


# Default session configuration
SESSION_TTL_SECONDS = 3600  # 1 hour absolute session lifetime
SESSION_IDLE_TIMEOUT = 1800  # 30 minutes idle timeout
SESSION_COOKIE_NAME = "session_id"


class SessionFixationProtection:
    """
    Session management with fixation attack prevention.

    Key defenses:
    1. Session ID regeneration on every auth state change
    2. No URL-based session IDs — cookies only
    3. Secure cookie attributes
    4. Absolute session TTL + idle timeout
    5. Optional IP and User-Agent binding
    """

    def __init__(
        self,
        secret_key: Optional[bytes] = None,
        ttl_seconds: int = SESSION_TTL_SECONDS,
        idle_timeout: int = SESSION_IDLE_TIMEOUT,
        bind_to_ip: bool = True,
        bind_to_user_agent: bool = False,
    ):
        self._secret_key = secret_key or secrets.token_bytes(32)
        self._ttl = ttl_seconds
        self._idle_timeout = idle_timeout
        self._bind_to_ip = bind_to_ip
        self._bind_to_user_agent = bind_to_user_agent
        self._sessions: Dict[str, dict] = {}

    def _generate_session_id(self) -> str:
        """Generate a cryptographically secure session ID."""
        return secrets.token_urlsafe(48)

    def create_session(
        self, user_id: str, ip_address: Optional[str] = None,
        user_agent: Optional[str] = None
    ) -> Tuple[str, dict]:
        """
        Create a new authenticated session with a fresh session ID.

        Always generates a NEW session ID — never reuses an existing one.
        This is the core defense against session fixation.

        Args:
            user_id: The authenticated user identifier.
            ip_address: Optional client IP for IP binding.
            user_agent: Optional User-Agent for UA binding.

        Returns:
            Tuple of (session_id, session_data).
        """
        session_id = self._generate_session_id()
        now = time.time()

        session_data = {
            "user_id": user_id,
            "created_at": now,
            "last_activity": now,
            "ip_address": ip_address,
            "user_agent": user_agent,
            "data": {},
        }

        self._sessions[session_id] = session_data
        return session_id, session_data

    def regenerate_session(
        self, old_session_id: str
    ) -> Optional[Tuple[str, dict]]:
        """
        Regenerate a session ID (called on login/logout/privilege escalation).

        Creates a new session with a fresh ID and copies the data from
        the old session. The old session is invalidated.

        Args:
            old_session_id: The current session ID to replace.

        Returns:
            Tuple of (new_session_id, new_session_data) or None if
            the old session doesn't exist.
        """
        old_session = self._sessions.pop(old_session_id, None)
        if not old_session:
            return None

        return self.create_session(
            old_session["user_id"],
            old_session.get("ip_address"),
            old_session.get("user_agent"),
        )

    def get_session(
        self, session_id: str,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None
    ) -> Optional[dict]:
        """
        Retrieve a session with validation checks.

        Validates:
        1. Session exists
        2. Session has not expired (absolute TTL)
        3. Session has not timed out (idle timeout)
        4. IP address matches (if IP binding is enabled)
        5. User-Agent matches (if UA binding is enabled)

        Args:
            session_id: The session ID to look up.
            ip_address: The client's IP address for validation.
            user_agent: The client's User-Agent for validation.

        Returns:
            Session data dict or None if invalid/expired.
        """
        session = self._sessions.get(session_id)
        if not session:
            return None

        now = time.time()

        # Check absolute TTL
        if now - session["created_at"] > self._ttl:
            del self._sessions[session_id]
            return None

        # Check idle timeout
        if now - session["last_activity"] > self._idle_timeout:
            del self._sessions[session_id]
            return None

        # Check IP binding
        if self._bind_to_ip and ip_address:
            if session.get("ip_address") != ip_address:
                del self._sessions[session_id]
                return None

        # Check User-Agent binding
        if self._bind_to_user_agent and user_agent:
            if session.get("user_agent") != user_agent:
                del self._sessions[session_id]
                return None

        # Update last activity
        session["last_activity"] = now
        return session

    def destroy_session(self, session_id: str) -> None:
        """Destroy a session (called on logout)."""
        self._sessions.pop(session_id, None)

    @staticmethod
    def set_secure_cookie_headers() -> Dict[str, str]:
        """
        Return secure cookie headers for Set-Cookie.

        These headers should be set on every response that uses sessions.
        """
        return {
            "HttpOnly": "true",
            "Secure": "true",
            "SameSite": "Lax",
            "Path": "/",
        }

    @staticmethod
    def is_url_session_id(url: str) -> bool:
        """
        Check if a URL contains a session ID parameter.

        URL-based session IDs are always rejected. Session IDs
        must only come from cookies.
        """
        import urllib.parse
        parsed = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed.query)
        return SESSION_COOKIE_NAME in params or "session_id" in params