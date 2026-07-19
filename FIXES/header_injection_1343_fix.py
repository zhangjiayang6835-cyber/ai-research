"""
Fix for Issue #1343 — Host Header Injection → Password Reset Poisoning
=====================================================================

Vulnerability: password reset endpoint constructs links using the untrusted
Host header. Attacker poisons the reset link sent to victim's email.

Fix: Host allow-list validation, password reset URL builder with validated
hostname, request middleware to reject invalid Host headers.
"""

from __future__ import annotations

import os
import re
from typing import Optional, Set

_DEFAULT_ALLOWED_HOSTS = os.environ.get(
    "VALIDATED_HOSTS",
    "localhost:5000,127.0.0.1:5000,app.example.com",
).split(",")

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


def _normalize_host(host: str) -> str:
    return host.strip().lower()


def _is_host_allowed(
    host: str,
    allowed_hosts: Optional[Set[str]] = None,
) -> bool:
    if allowed_hosts is None:
        allowed_hosts = {h.strip().lower() for h in _DEFAULT_ALLOWED_HOSTS}
    normalized = _normalize_host(host)
    if not normalized:
        return False
    if "\r" in normalized or "\n" in normalized:
        return False
    return normalized in allowed_hosts


def validate_host_header(
    host_header: str,
    allowed_hosts: Optional[Set[str]] = None,
) -> str:
    if not host_header or not host_header.strip():
        raise HostHeaderValidationError("Host header is empty")
    if "," in host_header:
        raise HostHeaderValidationError("Multiple Host headers detected")
    if any(ord(c) < 32 for c in host_header):
        raise HostHeaderValidationError("Host header contains control characters")
    match = _HOST_RE.match(host_header.strip())
    if not match:
        raise HostHeaderValidationError(f"Host header format invalid: {host_header!r}")
    if not _is_host_allowed(host_header, allowed_hosts):
        raise HostHeaderValidationError(f"Host header not in allow-list: {host_header!r}")
    return host_header.strip()


def build_password_reset_url(
    token: str,
    host: Optional[str] = None,
    allowed_hosts: Optional[Set[str]] = None,
) -> str:
    if host is not None:
        try:
            host = validate_host_header(host, allowed_hosts)
        except HostHeaderValidationError as e:
            raise PasswordResetPoisoningError(f"Cannot build reset URL: {e}") from e
    else:
        if allowed_hosts:
            host = next(iter(allowed_hosts))
        else:
            host = _DEFAULT_ALLOWED_HOSTS[0].strip()
    return f"https://{host}/reset?token={token}"


def sanitize_password_reset_link(
    raw_host: str,
    token: str,
    allowed_hosts: Optional[Set[str]] = None,
) -> str:
    validated = validate_host_header(raw_host, allowed_hosts)
    return build_password_reset_url(token, host=validated)
