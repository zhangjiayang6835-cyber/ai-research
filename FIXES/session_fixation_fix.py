"""
Session Fixation + Session ID in URL Fix
Bounty #780 ($120)
=========================================
Vulnerability: App accepts session ID from URL params (?sessionid=xyz),
and doesn't regenerate session after login. Attacker can fixate a session.

Fix: Regenerate session on login + reject URL-based session IDs.
"""

import secrets
import hmac
import hashlib
from typing import Dict, Optional
from urllib.parse import urlparse, parse_qs


class SecureSessionManager:
    """
    Session management that prevents session fixation attacks.
    
    Principles:
    1. Session ID only via Secure + HttpOnly cookies (never URL)
    2. Session ID regenerated on authentication (login)
    3. Old session data migrated to new session
    """

    def __init__(self, secret_key: str):
        self._secret_key = secret_key
        self._sessions: Dict[str, Dict] = {}  # session_id -> data
        self._cookie_name = "session_id"

    def create_session(self) -> str:
        """Create a new session with a cryptographically random ID."""
        session_id = self._generate_session_id()
        self._sessions[session_id] = {
            "_created": True,
            "_authenticated": False,
        }
        return session_id

    def regenerate_session(self, old_session_id: str) -> str:
        """
        Regenerate session ID after authentication.
        Migrates old session data to new ID.
        """
        old_data = self._sessions.pop(old_session_id, {})
        new_session_id = self._generate_session_id()

        # Mark as authenticated
        old_data["_authenticated"] = True
        self._sessions[new_session_id] = old_data

        return new_session_id

    def get_session(self, session_id: str) -> Optional[Dict]:
        """Get session data by ID."""
        return self._sessions.get(session_id)

    def destroy_session(self, session_id: str):
        """Destroy a session (logout)."""
        self._sessions.pop(session_id, None)

    def get_cookie_header(self, session_id: str, secure: bool = True) -> str:
        """
        Generate Secure + HttpOnly cookie header.
        Session ID is NEVER exposed in URL.
        """
        cookie = f"{self._cookie_name}={session_id}; Path=/; HttpOnly"
        if secure:
            cookie += "; Secure"
        cookie += "; SameSite=Lax"
        cookie += "; Max-Age=86400"  # 24 hours
        return cookie

    def _generate_session_id(self) -> str:
        """Generate a cryptographically random session ID."""
        return secrets.token_urlsafe(32)


class SessionFixationMiddleware:
    """
    Middleware that prevents session fixation via URL parameters.
    """

    def __init__(self, session_manager: SecureSessionManager):
        self._session_manager = session_manager

    def process_request(self, url: str, headers: Dict[str, str]) -> Dict[str, str]:
        """
        Process incoming request.
        - Rejects session IDs from URL parameters
        - Only accepts session IDs from cookies
        """
        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        # Check for session ID in URL (attack indicator)
        url_session_id = params.get("sessionid") or params.get("session_id")
        if url_session_id:
            # Reject URL-based session IDs and create new session
            new_session_id = self._session_manager.create_session()
            headers = dict(headers)
            headers["Set-Cookie"] = self._session_manager.get_cookie_header(
                new_session_id
            )
            # Log the attack attempt
            self._log_attack_attempt(url)
            return headers

        return headers

    def on_login(self, old_session_id: str) -> Dict[str, str]:
        """
        On successful login, regenerate session ID.
        """
        new_session_id = self._session_manager.regenerate_session(old_session_id)
        return {
            "Set-Cookie": self._session_manager.get_cookie_header(new_session_id),
            "X-Session-Regenerated": "true",
        }

    def on_logout(self, session_id: str) -> Dict[str, str]:
        """
        On logout, destroy session.
        """
        self._session_manager.destroy_session(session_id)
        return {
            "Set-Cookie": f"session_id=; Path=/; HttpOnly; Secure; Max-Age=0",
        }

    @staticmethod
    def _log_attack_attempt(url: str):
        """Log session fixation attack attempt."""
        import logging
        logging.warning(f"Session fixation attempt detected: URL contains sessionid parameter - {url}")


# ========== Usage Example ==========
if __name__ == "__main__":
    print("=== Session Fixation Prevention ===")
    print()

    session_manager = SecureSessionManager(secret_key="my_secret_key_12345")
    middleware = SessionFixationMiddleware(session_manager)

    # Attack scenario:
    # 1. Attacker creates a session: ?sessionid=attacker_session
    # 2. Attacker sends victim: https://example.com/login?sessionid=attacker_session
    # 3. Victim logs in, session not regenerated
    # 4. Attacker shares the same authenticated session

    print("Attack scenario:")
    print("  URL: https://example.com/login?sessionid=attacker_session_123")
    print()

    # With fix: URL-based session ID is rejected
    headers = middleware.process_request(
        "https://example.com/login?sessionid=attacker_session_123",
        {}
    )
    print("With fix:")
    print(f"  Set-Cookie: {headers.get('Set-Cookie', '(new session created)')}")
    print("  → URL-based session ID rejected, new session created")
    print()

    # With fix: Session regenerated on login
    old_session = session_manager.create_session()
    print(f"Before login: session_id = {old_session[:16]}...")
    print(f"  _authenticated = {session_manager.get_session(old_session).get('_authenticated')}")

    login_headers = middleware.on_login(old_session)
    print()
    print(f"After login: session regenerated")
    print(f"  {login_headers['Set-Cookie']}")
    print(f"  X-Session-Regenerated: true")
    print()

    print("=== Security Headers Summary ===")
    print("✓ Session ID: Cookie only (no URL params)")
    print("✓ Cookie: HttpOnly + Secure + SameSite=Lax")
    print("✓ Session: Regenerated on login")
    print("✓ Session: Destroyed on logout")
