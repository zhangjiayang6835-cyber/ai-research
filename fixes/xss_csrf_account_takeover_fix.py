"""Defense-in-depth fix for issue #343: XSS to CSRF account takeover.

The vulnerable chain has three links:

* reflected or stored user content renders as executable HTML/JavaScript;
* state-changing account actions accept cross-site requests without a token;
* login keeps an attacker-controlled session identifier alive.

This module provides framework-neutral helpers that break those links without
depending on a specific web framework.
"""

from __future__ import annotations

import html
import hmac
import secrets
from collections.abc import Callable, MutableMapping
from dataclasses import dataclass
from typing import Any


class AccountTakeoverGuardError(ValueError):
    """Raised when a request fails account takeover protections."""


def escape_html(value: Any) -> str:
    """Encode untrusted content before inserting it into an HTML response."""

    return html.escape(str(value), quote=True)


def render_profile_heading(display_name: Any) -> str:
    """Render profile data without allowing script execution."""

    return f"<h1>{escape_html(display_name)}</h1>"


def generate_csrf_token() -> str:
    """Return a high-entropy CSRF token suitable for storing in a session."""

    return secrets.token_urlsafe(32)


def validate_csrf_token(session_token: str | None, submitted_token: str | None) -> None:
    """Reject missing or mismatched CSRF tokens using constant-time compare."""

    if not session_token or not submitted_token:
        raise AccountTakeoverGuardError("Missing CSRF token")
    if not hmac.compare_digest(session_token, submitted_token):
        raise AccountTakeoverGuardError("Invalid CSRF token")


def rotate_session_on_login(
    session: MutableMapping[str, Any],
    *,
    user_id: str,
    token_factory: Callable[[], str] = generate_csrf_token,
) -> None:
    """Clear fixation-prone state and bind a fresh CSRF token to the login.

    Most frameworks regenerate the cookie identifier through their session
    backend. The portable part shown here is still important: remove stale
    attacker-controlled values and issue a new authenticated session context.
    """

    session.clear()
    session["user_id"] = user_id
    session["csrf_token"] = token_factory()
    session["authenticated"] = True


@dataclass
class Account:
    """Minimal account model used by the safe account-update helper."""

    user_id: str
    email: str
    display_name: str


def update_account_email(
    *,
    account: Account,
    session: MutableMapping[str, Any],
    submitted_csrf_token: str | None,
    new_email: str,
) -> Account:
    """Apply an account email change only for the logged-in owner with CSRF.

    This protects the high-impact state change that turns XSS plus CSRF into
    account takeover. The stored email remains plain data; HTML encoding is
    applied at render time, not by mutating persisted values.
    """

    if session.get("user_id") != account.user_id:
        raise AccountTakeoverGuardError("Authenticated user does not own account")

    validate_csrf_token(
        str(session.get("csrf_token") or ""),
        submitted_csrf_token,
    )

    normalized_email = new_email.strip()
    if "@" not in normalized_email or len(normalized_email) > 254:
        raise AccountTakeoverGuardError("Invalid email")

    account.email = normalized_email
    return account


def secure_session_cookie_options(*, https_only: bool = True) -> dict[str, Any]:
    """Return session-cookie flags that reduce XSS and CSRF blast radius."""

    return {
        "httponly": True,
        "secure": https_only,
        "samesite": "Strict",
        "path": "/",
    }


__all__ = [
    "Account",
    "AccountTakeoverGuardError",
    "escape_html",
    "generate_csrf_token",
    "render_profile_heading",
    "rotate_session_on_login",
    "secure_session_cookie_options",
    "update_account_email",
    "validate_csrf_token",
]
