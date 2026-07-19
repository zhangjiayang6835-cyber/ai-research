"""
Fix for Issue #1343 — Host Header Injection → Password Reset Poisoning
=======================================================================

Vulnerability
-------------
The password reset endpoint trusts the Host header when constructing
reset links. An attacker manipulates the Host header to point to an
attacker-controlled domain, causing the reset link to point there
instead. If the victim clicks the link, the attacker harvests the
reset token and compromises the account.

Fix Strategy
------------
1. Strict allow-list validation of the Host header.
2. Build reset links from validated host only; reject unknown hosts.
3. Strip CR/LF/control characters to prevent header injection.
4. Provide a safe fallback URL for the default host when none is specified.
"""

from __future__ import annotations

import re
from typing import Optional, Set


# ── Configuration ─────────────────────────────────────────────────────

DEFAULT_ALLOWED_HOSTS: Set[str] = {
    "localhost:5000",
    "app.example.com",
}

_RESET_PATH = "/reset"
_RESET_SCHEME = "https"

# Regex matching control characters that must be stripped
_CONTROL_CHAR_RE = re.compile(r"[\x00-\x1f\x7f]")


# ── Exception Types ──────────────────────────────────────────────────

class HostHeaderValidationError(ValueError):
    """Raised when the Host header fails validation."""


class PasswordResetPoisoningError(ValueError):
    """Raised when constructing a reset URL with a poisoned host."""


# ── Validation ───────────────────────────────────────────────────────

def _is_valid_host(host: str) -> bool:
    """Internal check: host has no CR/LF or control characters."""
    if not host:
        return False
    if "," in host:
        return False
    if _CONTROL_CHAR_RE.search(host):
        return False
    return True


def validate_host_header(
    host: str,
    allowed_hosts: Optional[Set[str]] = None,
) -> str:
    """Validate and return a trusted Host header.

    Args:
        host: The Host header value to validate.
        allowed_hosts: Set of allowed host:port values.

    Returns:
        The validated host string.

    Raises:
        HostHeaderValidationError: If the host is missing, contains
            CR/LF/control characters, or is not in the allow-list.
    """
    if allowed_hosts is None:
        allowed_hosts = DEFAULT_ALLOWED_HOSTS

    if not host:
        raise HostHeaderValidationError("Host header is empty or missing")

    if not _is_valid_host(host):
        raise HostHeaderValidationError(
            "Host header contains invalid characters"
        )

    # Reject multiple Host headers (comma-separated)
    if host not in allowed_hosts:
        raise HostHeaderValidationError(f"Host not allowed: {host}")

    return host


# ── Password Reset Link Construction ─────────────────────────────────

def sanitize_password_reset_link(
    host: str,
    token: str,
    allowed_hosts: Optional[Set[str]] = None,
) -> str:
    """Build a safe password reset URL after validating the host.

    Args:
        host: The Host header value.
        token: The password reset token.
        allowed_hosts: Set of allowed hosts.

    Returns:
        A safe HTTPS reset URL.

    Raises:
        HostHeaderValidationError: If the host is not allowed.
    """
    validated_host = validate_host_header(host, allowed_hosts)
    return f"{_RESET_SCHEME}://{validated_host}{_RESET_PATH}?token={token}"


def build_password_reset_url(
    token: str,
    host: Optional[str] = None,
    allowed_hosts: Optional[Set[str]] = None,
) -> str:
    """Build a password reset URL, defaulting to the first allowed host.

    This is the PRIMARY entry point for password reset link generation.
    It always validates the host and never trusts an unvalidated input.

    Args:
        token: The password reset token.
        host: Optional specific host (defaults to first allowed).
        allowed_hosts: Set of allowed hosts.

    Returns:
        A safe HTTPS reset URL.

    Raises:
        PasswordResetPoisoningError: If the host is not in the allow-list.
    """
    if allowed_hosts is None:
        allowed_hosts = DEFAULT_ALLOWED_HOSTS

    if host is not None:
        try:
            return sanitize_password_reset_link(host, token, allowed_hosts)
        except HostHeaderValidationError as e:
            raise PasswordResetPoisoningError(str(e)) from e

    # Default to first allowed host
    default_host = next(iter(allowed_hosts))
    return sanitize_password_reset_link(default_host, token, allowed_hosts)
