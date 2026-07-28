"""
session_token_url_fix.py — Session Fixation + Session ID in URL Fix

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
1. Reject session tokens in URL query parameters
2. Strip sensitive query parameters from URLs
3. Migrate one-time tokens from URL to secure cookies
4. Provide WSGI middleware to block session tokens in URLs
5. Regenerate session ID on every authentication (login/logout)
6. Set secure cookie attributes: HttpOnly, Secure, SameSite=Lax
"""

from __future__ import annotations

import secrets
import time
import urllib.parse
from collections import namedtuple
from dataclasses import dataclass, field
from typing import Dict, Optional, Set, Tuple
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

# ── Sensitive parameter names ──────────────────────────────────────────────

# Session / auth tokens that MUST NOT appear in URLs
SESSION_TOKEN_NAMES: frozenset = frozenset({
    "session_token", "session_id", "sessionid", "sid", "session",
    "access_token", "refresh_token", "id_token", "token",
    "one_time_token", "otp_token", "auth_token", "api_key",
    "phpsessid", "jsessionid", "aspsessionid",
})

# Parameters that should be stripped from logs/referrers
SENSITIVE_PARAM_NAMES: frozenset = frozenset({
    "session_token", "session_id", "sessionid", "sid", "session",
    "access_token", "refresh_token", "id_token", "token",
    "one_time_token", "otp_token", "auth_token", "api_key",
    "password", "passwd", "secret", "csrf_token", "xsrf_token",
    "phpsessid", "jsessionid", "aspsessionid",
})

# ── Exceptions ──────────────────────────────────────────────────────────────

class SessionTokenInUrlError(ValueError):
    """Raised when a session token is found in a URL query parameter.

    Session IDs and tokens must only be transmitted via secure cookies,
    never in URLs. URL-based tokens are vulnerable to:
    - Session fixation attacks
    - Leakage via Referer headers
    - Exposure in server logs and browser history
    """
    pass


# ── Clean URL result ────────────────────────────────────────────────────────

_StripResult = namedtuple("_StripResult", ["url", "removed_keys"])


class StripResult:
    """Result of stripping sensitive query parameters from a URL."""

    def __init__(self, url: str, removed_keys: Tuple[str, ...]):
        self.url = url
        self.removed_keys = removed_keys


# ── Core functions ──────────────────────────────────────────────────────────

def _parse_url_params(url: str):
    """Parse a URL into components, params dict, and fragment."""
    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)
    return parsed, params


def _build_url(scheme: str, netloc: str, path: str, params: dict, fragment: str) -> str:
    """Rebuild a URL from components, encoding query params."""
    query = urlencode(params, doseq=True) if params else ""
    return urlunparse((scheme, netloc, path, "", query, fragment))


def reject_session_tokens_in_url(url: str) -> None:
    """Check a URL for session tokens and raise if any are found.

    This is the first line of defense: before any request processing,
    verify that the URL does not contain session/auth tokens.

    Args:
        url: The URL to check.

    Raises:
        SessionTokenInUrlError: If a session token parameter is found.
    """
    parsed, params = _parse_url_params(url)
    for key in params:
        if key.lower() in SESSION_TOKEN_NAMES:
            raise SessionTokenInUrlError(
                f"Session token '{key}' detected in URL query parameter. "
                "Session tokens must only be transmitted via secure cookies."
            )


def strip_sensitive_query_params(url: str) -> StripResult:
    """Remove all sensitive query parameters from a URL.

    Preserves non-sensitive parameters and the URL fragment.

    Args:
        url: The URL to clean.

    Returns:
        A StripResult with:
            .url: The URL with sensitive parameters removed.
            .removed_keys: Tuple of parameter names that were removed.
    """
    parsed, params = _parse_url_params(url)
    removed: list[str] = []
    cleaned: dict[str, list[str]] = {}

    for key, values in params.items():
        if key.lower() in SENSITIVE_PARAM_NAMES:
            removed.append(key)
        else:
            cleaned[key] = values

    clean_url = _build_url(
        parsed.scheme, parsed.netloc, parsed.path,
        cleaned, parsed.fragment,
    )
    return StripResult(clean_url, tuple(removed))


def migrate_one_time_token_to_cookie(url: str) -> Tuple[str, Optional[str]]:
    """Migrate a one-time token from a URL query parameter to a cookie.

    Some flows (e.g., password reset, email verification) start with a
    token in the URL. This function extracts that token and returns a
    Set-Cookie header so the token can be transmitted securely.

    Args:
        url: The URL potentially containing a one_time_token parameter.

    Returns:
        A tuple of (clean_url, set_cookie_header).
        If no one_time_token is found, the URL is returned unchanged and
        cookie is None.
    """
    parsed, params = _parse_url_params(url)
    token_value = None

    # Extract the one_time_token
    cleaned_params: dict[str, list[str]] = {}
    for key, values in params.items():
        if key.lower() == "one_time_token":
            token_value = values[0] if values else None
        else:
            cleaned_params[key] = values

    if token_value is None:
        return url, None

    clean_url = _build_url(
        parsed.scheme, parsed.netloc, parsed.path,
        cleaned_params, parsed.fragment,
    )

    # Build a secure Set-Cookie header
    cookie = (
        f"one_time_token={token_value}; "
        f"HttpOnly; Secure; SameSite=Lax; Path=/; "
        f"Max-Age=300"
    )

    return clean_url, cookie


# ── WSGI Middleware ─────────────────────────────────────────────────────────

class SessionTokenURLGuard:
    """WSGI middleware that blocks requests with session tokens in the URL.

    Applied as a layer before the main application, this guard inspects
    the QUERY_STRING of every incoming request and returns a 400 Bad
    Request if any session/auth token parameter is detected.

    Usage:
        app = SessionTokenURLGuard(app)  # wrap your WSGI app
    """

    def __init__(self, app):
        self._app = app

    def __call__(self, environ, start_response):
        query_string = environ.get("QUERY_STRING", "")
        if query_string:
            params = parse_qs(query_string, keep_blank_values=True)
            for key in params:
                if key.lower() in SESSION_TOKEN_NAMES:
                    body = (
                        f"Session token '{key}' detected in URL. "
                        "Session tokens must only be transmitted via "
                        "secure cookies.".encode("utf-8")
                    )
                    headers = [
                        ("Content-Type", "text/plain; charset=utf-8"),
                        ("Cache-Control", "no-store"),
                        ("Content-Length", str(len(body))),
                    ]
                    start_response("400 Bad Request", headers)
                    return [body]

        # No session tokens in URL — pass through to the app
        return self._app(environ, start_response)


# ── SecureSessionManager (for use in app code) ──────────────────────────────

@dataclass
class SecureSessionConfig:
    """Configuration for secure session management."""
    session_length: int = 64       # bytes of entropy for session IDs
    session_lifetime: int = 3600    # seconds before absolute expiry
    idle_timeout: int = 1800        # seconds of inactivity before expiry
    http_only: bool = True
    secure: bool = True
    same_site: str = "Lax"
    path: str = "/"
    domain: Optional[str] = None
    bind_to_ip: bool = True
    bind_to_user_agent: bool = False


class SecureSessionManager:
    """Session manager with fixation attack prevention.

    Key defenses:
    1. Session ID regeneration on every auth state change
    2. No URL-based session IDs — cookies only
    3. Secure cookie attributes (HttpOnly, Secure, SameSite)
    4. Absolute session TTL + idle timeout
    5. Optional IP and User-Agent binding (origin validation)
    """

    def __init__(self, config: Optional[SecureSessionConfig] = None):
        self.config = config or SecureSessionConfig()
        self._sessions: Dict[str, dict] = {}

    def generate_session_id(self) -> str:
        """Generate a cryptographically secure session ID."""
        return secrets.token_urlsafe(self.config.session_length)

    def create_session(
        self,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
    ) -> str:
        """Create a new unauthenticated session with a fresh ID.

        Always generates a NEW session ID — never accepts one from
        the client. This is the core defense against session fixation.
        """
        session_id = self.generate_session_id()
        now = time.time()
        self._sessions[session_id] = {
            "created_at": now,
            "last_activity": now,
            "ip_address": ip_address,
            "user_agent": user_agent,
            "data": {},
            "is_authenticated": False,
        }
        return session_id

    def get_session(
        self,
        session_id: str,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
    ) -> Optional[dict]:
        """Retrieve a session with validation checks.

        Validates:
        1. Session exists
        2. Session has not expired (absolute TTL)
        3. Session has not timed out (idle timeout)
        4. IP address matches (if IP binding is enabled)
        5. User-Agent matches (if UA binding is enabled)
        """
        session = self._sessions.get(session_id)
        if not session:
            return None

        now = time.time()

        # Check absolute TTL
        if now - session["created_at"] > self.config.session_lifetime:
            del self._sessions[session_id]
            return None

        # Check idle timeout
        if now - session["last_activity"] > self.config.idle_timeout:
            del self._sessions[session_id]
            return None

        # Check IP binding (origin validation)
        if self.config.bind_to_ip and ip_address:
            if session.get("ip_address") != ip_address:
                del self._sessions[session_id]
                return None

        # Check User-Agent binding (origin validation)
        if self.config.bind_to_user_agent and user_agent:
            if session.get("user_agent") != user_agent:
                del self._sessions[session_id]
                return None

        # Update last activity
        session["last_activity"] = now
        return session

    def regenerate_session(self, old_session_id: str) -> Optional[str]:
        """Regenerate a session ID (called on login/logout).

        Creates a new session with a fresh ID and copies data from
        the old session. The old session is invalidated.
        """
        old_session = self._sessions.pop(old_session_id, None)
        if not old_session:
            return None

        new_session_id = self.generate_session_id()
        now = time.time()
        self._sessions[new_session_id] = {
            "created_at": now,
            "last_activity": now,
            "ip_address": old_session.get("ip_address"),
            "user_agent": old_session.get("user_agent"),
            "data": old_session.get("data", {}),
            "is_authenticated": True,
        }
        return new_session_id

    def login(
        self,
        session_id: str,
        user_data: dict,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
    ) -> str:
        """Handle login with session regeneration.

        1. Validates the current session
        2. Regenerates the session ID (prevents fixation)
        3. Stores user authentication data

        Returns the new session ID.
        """
        # Validate existing session
        if session_id not in self._sessions:
            # Create a new session if none exists
            new_sid = self.create_session(
                ip_address=ip_address, user_agent=user_agent
            )
            self._sessions[new_sid]["data"]["user"] = user_data
            self._sessions[new_sid]["is_authenticated"] = True
            return new_sid

        # Regenerate session ID
        new_session_id = self.regenerate_session(session_id)
        if new_session_id is None:
            new_session_id = self.create_session(
                ip_address=ip_address, user_agent=user_agent
            )

        # Update IP/UA binding
        if ip_address:
            self._sessions[new_session_id]["ip_address"] = ip_address
        if user_agent:
            self._sessions[new_session_id]["user_agent"] = user_agent

        # Store user data
        self._sessions[new_session_id]["data"]["user"] = user_data
        self._sessions[new_session_id]["is_authenticated"] = True
        return new_session_id

    def logout(self, session_id: str) -> None:
        """Destroy a session on logout."""
        self._sessions.pop(session_id, None)

    def destroy_session(self, session_id: str) -> None:
        """Alias for logout."""
        self.logout(session_id)

    def get_cookie_header(self, session_id: str, cookie_name: str = "session_id") -> str:
        """Generate a secure Set-Cookie header.

        Includes:
        - HttpOnly: Prevents JavaScript access (mitigates XSS exfiltration)
        - Secure: Only sent over HTTPS
        - SameSite=Lax: CSRF mitigation
        - Path=/: Available across the site
        - Max-Age: Session lifetime
        """
        parts = [f"{cookie_name}={session_id}"]

        if self.config.http_only:
            parts.append("HttpOnly")
        if self.config.secure:
            parts.append("Secure")
        if self.config.same_site:
            parts.append(f"SameSite={self.config.same_site}")
        if self.config.path:
            parts.append(f"Path={self.config.path}")
        if self.config.domain:
            parts.append(f"Domain={self.config.domain}")

        parts.append(f"Max-Age={self.config.session_lifetime}")

        return "; ".join(parts)

    def get_session_count(self) -> int:
        """Return the number of active sessions."""
        return len(self._sessions)


# ── SessionFixationGuard (combined protection) ────────────────────────────

class SessionFixationGuard:
    """Combined session fixation protection guard.

    Integrates:
    - URL session ID rejection
    - Session regeneration on login
    - Secure cookies
    - Origin validation (IP/UA)
    """

    def __init__(self):
        self.session_manager = SecureSessionManager()

    def process_request(
        self,
        cookies: Dict[str, str],
        url_params: Dict[str, str],
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
    ) -> Optional[str]:
        """Process an incoming request.

        1. Rejects session IDs in URL params
        2. Retrieves session from cookie
        3. Validates session (TTL, origin)

        Returns the session ID or None if no valid session.
        """
        # Reject session IDs in URL parameters
        for param in url_params:
            if param.lower() in SESSION_TOKEN_NAMES:
                raise SessionTokenInUrlError(
                    f"Session token '{param}' in URL rejected"
                )

        # Get session from cookie
        session_id = cookies.get("session_id") or cookies.get("sessionid")
        if not session_id:
            return None

        # Validate session
        session = self.session_manager.get_session(
            session_id,
            ip_address=ip_address,
            user_agent=user_agent,
        )
        if not session:
            return None

        return session_id

    def handle_login(
        self,
        session_id: str,
        user_data: dict,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
    ) -> str:
        """Handle login with session regeneration."""
        return self.session_manager.login(
            session_id, user_data,
            ip_address=ip_address,
            user_agent=user_agent,
        )

    def get_response_cookies(
        self,
        session_id: str,
        cookie_name: str = "session_id",
    ) -> Dict[str, str]:
        """Get response cookie headers."""
        return {
            "Set-Cookie": self.session_manager.get_cookie_header(
                session_id, cookie_name=cookie_name
            )
        }


# ── Self-test ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    # Test session token rejection
    try:
        reject_session_tokens_in_url(
            "https://example.test/callback?session_token=secret"
        )
        print("FAIL: should have raised SessionTokenInUrlError")
    except SessionTokenInUrlError as e:
        assert "session_token" in str(e)
        print("PASS: reject_session_tokens_in_url")

    # Test strip_sensitive_query_params
    result = strip_sensitive_query_params(
        "https://example.test/search?q=public&access_token=secret&page=2#top"
    )
    assert result.url == "https://example.test/search?q=public&page=2#top"
    assert "access_token" in result.removed_keys
    print("PASS: strip_sensitive_query_params")

    # Test allow normal params
    url = "https://example.test/search?q=public&page=2"
    reject_session_tokens_in_url(url)
    result2 = strip_sensitive_query_params(url)
    assert result2.url == url
    print("PASS: allows normal query parameters")

    # Test one-time token migration
    clean_url, cookie = migrate_one_time_token_to_cookie(
        "https://example.test/callback?one_time_token=abc123&next=%2Fhome"
    )
    assert clean_url == "https://example.test/callback?next=%2Fhome"
    assert cookie is not None
    assert "abc123" in cookie
    assert "HttpOnly" in cookie
    assert "Secure" in cookie
    assert "SameSite=Lax" in cookie
    print("PASS: migrate_one_time_token_to_cookie")

    # Test WSGI guard
    events = []
    def app(environ, start_response):
        start_response("200 OK", [("Content-Type", "text/plain")])
        return [b"ok"]
    def start_response(status, headers):
        events.append((status, dict(headers)))

    guard = SessionTokenURLGuard(app)
    body = b"".join(guard({"QUERY_STRING": "token=secret"}, start_response))
    assert events[-1][0] == "400 Bad Request"
    assert events[-1][1]["Cache-Control"] == "no-store"
    assert body.startswith(b"Session token")
    print("PASS: WSGI guard blocks token in URL")

    # Test WSGI guard allows normal query
    events2 = []
    def start_response2(status, headers):
        events2.append((status, dict(headers)))
    body2 = b"".join(guard({"QUERY_STRING": "q=public"}, start_response2))
    assert events2[-1][0] == "200 OK"
    assert body2 == b"ok"
    print("PASS: WSGI guard allows normal query")

    # Test session manager
    mgr = SecureSessionManager()
    sid = mgr.create_session(ip_address="192.168.1.1")
    assert mgr.get_session(sid, ip_address="192.168.1.1") is not None
    assert mgr.get_session(sid, ip_address="10.0.0.1") is None  # IP mismatch
    print("PASS: IP binding")

    new_sid = mgr.login(sid, {"username": "admin"}, ip_address="192.168.1.1")
    assert new_sid != sid  # Session regenerated
    assert mgr.get_session(sid, ip_address="192.168.1.1") is None  # Old invalid
    assert mgr.get_session(new_sid, ip_address="192.168.1.1") is not None
    print("PASS: session regeneration on login")

    cookie = mgr.get_cookie_header(new_sid)
    assert "HttpOnly" in cookie
    assert "Secure" in cookie
    assert "SameSite=Lax" in cookie
    print("PASS: secure cookie headers")

    print("\nAll tests passed!")
