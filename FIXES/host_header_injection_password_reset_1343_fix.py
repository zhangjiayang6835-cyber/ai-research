"""
Fix for Issue #1343 — Host Header Injection → Password Reset Poisoning
=====================================================================

Vulnerability
-------------
The password reset endpoint constructs reset links using the untrusted
``Host`` header from the HTTP request. An attacker can supply a malicious
``Host`` header (e.g. ``Host: evil.com``) to poison the reset link sent
to the victim's email. When the victim clicks the link, the reset token
is delivered to the attacker-controlled domain.

Root Cause
----------
The application reads ``request.host`` or
``request.headers.get('Host')`` directly without validation when
constructing password reset URLs.

Fix Strategy
------------
1. Maintain an explicit allow-list of trusted hostnames — never
   inferred from the request headers.
2. Validate the Host header against the allow-list on every request
   using a ``before_request`` middleware.
3. Build password reset URLs using a helper that only uses the
   validated hostname, never the raw header.
4. Reject requests with multiple Host headers, CR/LF characters,
   or non-ASCII bytes in the host field.
"""

from __future__ import annotations

import os
import re
from typing import Optional, Set

# ── Configuration ─────────────────────────────────────────────────────

# Trusted hostnames — configure via environment variable (comma-separated)
_DEFAULT_ALLOWED_HOSTS = os.environ.get(
    "VALIDATED_HOSTS",
    "localhost:5000,127.0.0.1:5000,app.example.com",
).split(",")

# RFC 3986 reg-name + optional port; disallows CR/LF, spaces, '@', '/'
_HOST_RE = re.compile(
    r"^(?P<host>[A-Za-z0-9](?:[A-Za-z0-9\-\.]{0,253}[A-Za-z0-9])?)"
    r"(?::(?P<port>[0-9]{1,5}))?$"
)


class SecurityError(Exception):
    """Base security error."""


class HostHeaderValidationError(ValueError):
    """Raised when the Host header fails validation."""


class PasswordResetPoisoningError(SecurityError):
    """Raised when password reset link poisoning is detected."""


# ── Host Validation ───────────────────────────────────────────────────

def _normalize_host(host: str) -> str:
    """Strip whitespace and trailing port for comparison."""
    host = host.strip().lower()
    return host


def _is_host_allowed(
    host: str,
    allowed_hosts: Optional[Set[str]] = None,
) -> bool:
    """Check if host is in the allow-list after normalization."""
    if allowed_hosts is None:
        allowed_hosts = {h.strip().lower() for h in _DEFAULT_ALLOWED_HOSTS}

    normalized = _normalize_host(host)

    # Reject empty host
    if not normalized:
        return False

    # Reject CR/LF injection
    if "\r" in normalized or "\n" in normalized:
        return False

    return normalized in allowed_hosts


def validate_host_header(
    host_header: str,
    allowed_hosts: Optional[Set[str]] = None,
) -> str:
    """Validate a Host header value.

    Args:
        host_header: Raw Host header value from the request.
        allowed_hosts: Optional set of allowed hostnames.

    Returns:
        The validated, normalized hostname.

    Raises:
        HostHeaderValidationError: If the header is invalid or
            not in the allow-list.
    """
    if not host_header or not host_header.strip():
        raise HostHeaderValidationError("Host header is empty")

    # Reject multiple Host headers (comma-separated smuggling)
    if "," in host_header:
        raise HostHeaderValidationError(
            "Multiple Host headers detected"
        )

    # Reject control characters
    if any(ord(c) < 32 for c in host_header):
        raise HostHeaderValidationError(
            "Host header contains control characters"
        )

    # RFC 3986 format validation
    match = _HOST_RE.match(host_header.strip())
    if not match:
        raise HostHeaderValidationError(
            f"Host header format invalid: {host_header!r}"
        )

    # Allow-list check
    if not _is_host_allowed(host_header, allowed_hosts):
        raise HostHeaderValidationError(
            f"Host header not in allow-list: {host_header!r}"
        )

    return host_header.strip()


# ── Password Reset URL Builder ───────────────────────────────────────

def build_password_reset_url(
    token: str,
    host: Optional[str] = None,
    allowed_hosts: Optional[Set[str]] = None,
) -> str:
    """Build a password reset URL using only validated hostnames.

    Args:
        token: The password reset token.
        host: Optional validated hostname. If None, uses
            the first entry from the allowed hosts list.
        allowed_hosts: Optional set of allowed hostnames.

    Returns:
        A secure password reset URL.

    Raises:
        PasswordResetPoisoningError: If the host is not validated.
    """
    if host is not None:
        try:
            host = validate_host_header(host, allowed_hosts)
        except HostHeaderValidationError as e:
            raise PasswordResetPoisoningError(
                f"Cannot build reset URL: {e}"
            ) from e
    else:
        # Fall back to first allowed host
        if allowed_hosts:
            host = next(iter(allowed_hosts))
        else:
            host = _DEFAULT_ALLOWED_HOSTS[0].strip()

    return f"https://{host}/reset?token={token}"


# ── Flask Middleware Helpers ──────────────────────────────────────────

def validate_host_middleware(environ: dict) -> Optional[str]:
    """WSGI middleware-level Host header validation.

    Returns an error response body if validation fails, or None if
    the header is valid.
    """
    raw_host = environ.get("HTTP_HOST", "")
    try:
        validate_host_header(raw_host)
    except HostHeaderValidationError:
        return "Invalid Host header"
    return None


def sanitize_password_reset_link(
    raw_host: str,
    token: str,
    allowed_hosts: Optional[Set[str]] = None,
) -> str:
    """Safely build a password reset link from a raw Host header.

    This is the primary entry point for application code that needs
    to send password reset emails.

    Args:
        raw_host: The raw Host header from the request.
        token: The password reset token.
        allowed_hosts: Optional set of allowed hostnames.

    Returns:
        A secure reset URL with validated host.
    """
    validated = validate_host_header(raw_host, allowed_hosts)
    return build_password_reset_url(token, host=validated)
