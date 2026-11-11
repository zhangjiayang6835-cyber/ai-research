"""
Fix for Issue #664 — OAuth 2.0 CSRF → Account Takeover via State Bypass
========================================================================

Vulnerability
-------------
The OAuth callback endpoint does not validate the ``state`` parameter.
An attacker can craft a malicious OAuth authorization URL that, when
followed by a victim, binds the attacker's GitHub (or other provider)
account to the victim's application account — full account takeover.

Root cause
----------
1. No ``state`` parameter is generated or validated during the OAuth flow.
2. The callback handler trusts any ``code`` and ``state`` returned by the
   authorization provider without verifying it matches the original request.
3. No PKCE (RFC 7636) is used, so an intercepted authorization code can be
   exchanged for an access token by any party.

Fix Strategy
------------
1. Generate a cryptographically random ``state`` value on every
   authorization request and bind it to the user's session.
2. Validate the ``state`` on the callback — reject if missing, expired,
   or not bound to the current session.
3. Enforce PKCE (S256) for all authorization requests so that even if
   the authorization code is intercepted, the attacker cannot exchange it
   without the ``code_verifier``.
4. Use the Authorization Code Flow exclusively — Implicit Grant
   (``response_type=token``) is banned.
5. Validate redirect_uri with exact string match against registered URIs.

This module provides a drop-in ``SecureOAuthHandler`` that can be mounted
on any Flask / FastAPI / aiohttp application.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import os
import secrets
import time
from dataclasses import dataclass, field
from typing import Any, Dict, Optional, Set, Tuple
from urllib.parse import urlsplit, urlencode, urlunparse


# ── Constants ────────────────────────────────────────────────────────

CODE_CHALLENGE_METHOD = "S256"
STATE_TTL_SECONDS = 300          # 5 min
AUTH_CODE_TTL_SECONDS = 300      # 5 min
PKCE_MIN_VERIFIER_LEN = 43
PKCE_MAX_VERIFIER_LEN = 128


# ── Errors ───────────────────────────────────────────────────────────

class OAuthCSRFError(Exception):
    """Raised when OAuth state / CSRF validation fails."""


class OAuthPKCEError(Exception):
    """Raised when PKCE verification fails."""


class OAuthRedirectURIError(Exception):
    """Raised when redirect_uri does not match a registered URI."""


# ── PKCE helpers (RFC 7636) ──────────────────────────────────────────

def generate_code_verifier(length: int = 43) -> str:
    """Generate a cryptographically secure code_verifier (43–128 chars)."""
    if length < PKCE_MIN_VERIFIER_LEN or length > PKCE_MAX_VERIFIER_LEN:
        raise ValueError(
            f"code_verifier length must be {PKCE_MIN_VERIFIER_LEN}–"
            f"{PKCE_MAX_VERIFIER_LEN}"
        )
    raw = secrets.token_bytes((length * 3) // 4)
    allowed = (
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~"
    )
    verifier = ""
    for byte in raw:
        verifier += chr(allowed[byte % len(allowed)])
    return verifier[:length]


def compute_code_challenge(verifier: str) -> str:
    """S256 challenge = BASE64URL(SHA256(verifier))."""
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")


def verify_pkce(verifier: str, expected_challenge: str) -> bool:
    """Constant-time PKCE S256 verification. Rejects plain method."""
    if not (PKCE_MIN_VERIFIER_LEN <= len(verifier) <= PKCE_MAX_VERIFIER_LEN):
        return False
    derived = compute_code_challenge(verifier)
    return hmac.compare_digest(derived, expected_challenge)


# ── Redirect URI validation ──────────────────────────────────────────

def validate_redirect_uri(uri: str, registered_uris: Set[str]) -> None:
    """Exact-match redirect_uri validation (RFC 9700 §2.1)."""
    parsed = urlsplit(uri)
    if not parsed.scheme or not parsed.netloc:
        raise OAuthRedirectURIError("redirect_uri must be absolute")
    if parsed.scheme.lower() not in ("https", "http"):
        raise OAuthRedirectURIError("redirect_uri scheme must be http(s)")
    if parsed.fragment:
        raise OAuthRedirectURIError("redirect_uri must not contain fragment")
    if uri not in registered_uris:
        raise OAuthRedirectURIError("redirect_uri not registered")


# ── State manager ────────────────────────────────────────────────────

@dataclass
class _StateRecord:
    session_id: str
    created_at: float
    extra: Dict[str, Any] = field(default_factory=dict)


class StateManager:
    """Store and validate OAuth state values bound to sessions."""

    def __init__(self) -> None:
        self._states: Dict[str, _StateRecord] = {}

    def generate(self, session_id: str, extra: Optional[Dict] = None) -> str:
        """Generate a cryptographically random state bound to session_id."""
        state = secrets.token_urlsafe(32)  # 256-bit entropy
        self._states[state] = _StateRecord(
            session_id=session_id,
            created_at=time.time(),
            extra=extra or {},
        )
        return state

    def validate(self, state: str, session_id: str) -> Dict[str, Any]:
        """Validate state — one-time use, TTL check, session binding."""
        record = self._states.pop(state, None)
        if record is None:
            raise OAuthCSRFError(
                "state parameter missing or already used (possible CSRF)"
            )
        age = time.time() - record.created_at
        if age > STATE_TTL_SECONDS:
            raise OAuthCSRFError("state parameter expired")
        if record.session_id != session_id:
            raise OAuthCSRFError("state not bound to current session")
        return record.extra


# ── Secure OAuth handler ─────────────────────────────────────────────

@dataclass
class OAuthConfig:
    client_id: str
    redirect_uri: str
    scopes: Set[str] = field(default_factory=lambda: {"openid", "profile"})
    registered_redirect_uris: Set[str] = field(default_factory=set)
    authorization_endpoint: str = ""
    token_endpoint: str = ""


class SecureOAuthHandler:
    """
    Full OAuth 2.0 + PKCE + State CSRF protection.

    Usage:
        handler = SecureOAuthHandler(config, state_manager)
        auth_url, code_verifier, state = handler.build_authorization_url(
            session_id="sess_abc",
        )
        # redirect user to auth_url
        # on callback:
        handler.handle_callback(session_id="sess_abc", code="...", state="...")
    """

    def __init__(self, config: OAuthConfig, state_mgr: Optional[StateManager] = None):
        self.config = config
        self.state_mgr = state_mgr or StateManager()
        self._auth_codes: Dict[str, Dict[str, Any]] = {}

    # ---- Authorization request ----------------------------------------

    def build_authorization_url(
        self,
        session_id: str,
        redirect_uri: Optional[str] = None,
        extra_state_data: Optional[Dict[str, Any]] = None,
    ) -> Tuple[str, str, str]:
        """
        Build the OAuth authorization URL with PKCE + state.

        Returns: (auth_url, code_verifier, state)
        """
        rd_uri = redirect_uri or self.config.redirect_uri
        validate_redirect_uri(rd_uri, self.config.registered_redirect_uris or {rd_uri})

        # Generate state bound to session
        state = self.state_mgr.generate(session_id, extra_state_data)

        # Generate PKCE parameters
        code_verifier = generate_code_verifier()
        code_challenge = compute_code_challenge(code_verifier)

        # Build authorization URL (Authorization Code Flow only)
        params = {
            "response_type": "code",
            "client_id": self.config.client_id,
            "redirect_uri": rd_uri,
            "scope": " ".join(sorted(self.config.scopes)),
            "state": state,
            "code_challenge": code_challenge,
            "code_challenge_method": CODE_CHALLENGE_METHOD,
        }

        parsed = urlsplit(self.config.authorization_endpoint)
        auth_url = urlunparse(parsed._replace(query=urlencode(params)))

        return auth_url, code_verifier, state

    # ---- Callback handling --------------------------------------------

    def store_auth_code(
        self,
        code: str,
        *,
        client_id: str,
        redirect_uri: str,
        code_challenge: str,
        scope: str,
        subject: str,
    ) -> None:
        """
        Store an authorization code issued by the provider.

        In a real integration this would be called after the provider
        redirects back with ?code=…&state=….  Here we simulate the
        intermediate step of capturing the code before token exchange.
        """
        self._auth_codes[code] = {
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "code_challenge": code_challenge,
            "scope": scope,
            "subject": subject,
            "expires_at": time.time() + AUTH_CODE_TTL_SECONDS,
        }

    def handle_callback(
        self,
        session_id: str,
        code: str,
        state: str,
        code_verifier: str,
        redirect_uri: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Handle the OAuth callback — validate state, verify PKCE, return token info.

        This replaces the vulnerable pattern of trusting any ``code``
        and ``state`` from the provider without server-side validation.
        """
        rd_uri = redirect_uri or self.config.redirect_uri

        # 1. Validate state (CSRF protection)
        extra = self.state_mgr.validate(state, session_id)

        # 2. Look up stored auth code
        record = self._auth_codes.get(code)
        if record is None:
            raise OAuthCSRFError("unknown authorization code")

        # 3. Verify PKCE (prevents code interception attacks)
        if not verify_pkce(code_verifier, record["code_challenge"]):
            raise OAuthPKCEError("PKCE verification failed — code may have been intercepted")

        # 4. Verify redirect_uri match
        if record["redirect_uri"] != rd_uri:
            raise OAuthRedirectURIError("redirect_uri mismatch on callback")

        # 5. Check expiry
        if time.time() > record["expires_at"]:
            raise OAuthCSRFError("authorization code expired")

        # 6. Burn the code (single-use)
        self._auth_codes.pop(code, None)

        return {
            "sub": record["subject"],
            "scope": record["scope"],
            "extra": extra,
            "pkce_verified": True,
            "state_validated": True,
        }

    # ---- Implicit flow ban (for documentation / middleware) -----------

    @staticmethod
    def reject_implicit_flow(response_type: str) -> None:
        """
        Explicitly reject Implicit / Hybrid flows.

        Per OAuth 2.1 / RFC 9700, ``response_type=token`` and
        ``response_type=code id_token token`` MUST NOT be accepted.
        """
        if response_type != "code":
            raise OAuthCSRFError(
                f"response_type={response_type!r} is not supported. "
                "Use response_type=code with PKCE."
            )


# ── Self-tests ──────────────────────────────────────────────────────

def _run_self_tests() -> None:
    cfg = OAuthConfig(
        client_id="test-client",
        redirect_uri="https://app.example.com/callback",
        scopes={"openid", "profile"},
        registered_redirect_uris={"https://app.example.com/callback"},
        authorization_endpoint="https://auth.example.com/authorize",
        token_endpoint="https://auth.example.com/token",
    )
    sm = StateManager()
    handler = SecureOAuthHandler(cfg, sm)

    # Test 1: State generation + validation
    state = sm.generate("sess-1")
    data = sm.validate(state, "sess-1")
    assert data == {}

    # Test 2: State reuse rejected
    try:
        sm.validate(state, "sess-1")
        assert False, "should reject reused state"
    except OAuthCSRFError:
        pass

    # Test 3: Wrong session rejected
    new_state = sm.generate("sess-2")
    try:
        sm.validate(new_state, "sess-wrong")
        assert False, "should reject wrong session"
    except OAuthCSRFError:
        pass

    # Test 4: PKCE round-trip
    verifier = generate_code_verifier()
    challenge = compute_code_challenge(verifier)
    assert verify_pkce(verifier, challenge)
    assert not verify_pkce("wrong-verifier", challenge)

    # Test 5: Implicit flow banned
    SecureOAuthHandler.reject_implicit_flow("token")

    # Test 6: Redirect URI exact match
    validate_redirect_uri("https://app.example.com/callback", {"https://app.example.com/callback"})
    try:
        validate_redirect_uri("https://evil.com/callback", {"https://app.example.com/callback"})
        assert False
    except OAuthRedirectURIError:
        pass

    # Test 7: Full flow
    auth_url, verifier, state = handler.build_authorization_url("sess-1")
    assert "?code_challenge=" in auth_url
    assert "response_type=code" in auth_url
    assert "#access_token" not in auth_url  # no implicit token leak

    # Simulate provider callback
    handler.store_auth_code(
        "auth-code-xyz",
        client_id="test-client",
        redirect_uri="https://app.example.com/callback",
        code_challenge=compute_code_challenge(verifier),
        scope="openid profile",
        subject="user-42",
    )
    result = handler.handle_callback(
        session_id="sess-1",
        code="auth-code-xyz",
        state=state,
        code_verifier=verifier,
    )
    assert result["pkce_verified"]
    assert result["state_validated"]

    print("All 7 OAuth CSRF + PKCE fix self-tests passed.")


if __name__ == "__main__":
    _run_self_tests()
