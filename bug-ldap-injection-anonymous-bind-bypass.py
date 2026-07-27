#!/usr/bin/env python3
"""
Bug Fix: LDAP Injection → Anonymous Bind Bypass

Difficulty: Hard | Bounty: $120

Vulnerability Description:
    LDAP queries were being constructed by directly concatenating user input,
    allowing attackers to inject LDAP filter metacharacters. This could lead
    to authentication bypass via anonymous bind techniques (e.g., injecting
    `)(uid=*)` or similar payloads to match any entry, or forcing empty/null
    bind credentials).

Fix Summary:
    1. Parameterize / sanitize all user inputs before embedding them in LDAP
       filters using RFC 4515-compliant escaping.
    2. Validate username format (allowlist) before any LDAP interaction.
    3. Enforce non-empty password — reject anonymous bind attempts explicitly.
    4. Use structured filter construction helpers to avoid raw string building.
    5. Verify bind success by performing an authenticated lookup after bind.

References:
    - OWASP LDAP Injection Prevention Cheat Sheet
    - RFC 4515 (LDAP String Representation of Search Filters)

Target file: bug-ldap-injection-anonymous-bind-bypass.py
"""

import re
import logging
import ssl
from typing import Optional, Tuple, Dict, Any
from functools import wraps

# ldap3 is the recommended modern LDAP library for Python
try:
    from ldap3 import Server, Connection, ALL, SUBTREE, ALL_ATTRIBUTES
    from ldap3.core.exceptions import LDAPException
except ImportError:
    # Graceful fallback: allow module import without ldap3 installed
    # (useful for static analysis / CI linting)
    Server = None
    Connection = None
    ALL = None
    SUBTREE = None
    ALL_ATTRIBUTES = None
    LDAPException = Exception

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Allowlist pattern for LDAP usernames: alphanumeric, dot, hyphen, underscore
# This rejects any LDAP filter metacharacters at the validation layer.
USERNAME_ALLOWLIST = re.compile(r"^[a-zA-Z0-9._-]{1,128}$")

# Minimum password length to prevent trivial/empty passwords
MIN_PASSWORD_LENGTH = 1
MAX_PASSWORD_LENGTH = 512

# LDAP filter metacharacters per RFC 4515 that must be escaped
LDAP_FILTER_METACHARS = {
    "\\": "\\5c",
    "*": "\\2a",
    "(": "\\28",
    ")": "\\29",
    "\x00": "\\00",
}


# ---------------------------------------------------------------------------
# Input Validation & Sanitization
# ---------------------------------------------------------------------------

class LDAPSecurityError(Exception):
    """Raised when a security violation is detected during LDAP operations."""
    pass


class InputValidationError(LDAPSecurityError):
    """Raised when user input fails validation."""
    pass


class AuthenticationError(LDAPSecurityError):
    """Raised when LDAP authentication fails."""
    pass


def escape_ldap_filter(value: str) -> str:
    """
    Escape LDAP filter metacharacters in a user-supplied string per RFC 4515.

    This prevents LDAP injection by ensuring that characters like *, (, ),
    \\, and NUL are represented as their hex-encoded equivalents.

    Args:
        value: The raw user input string to escape.

    Returns:
        The escaped string safe for inclusion in an LDAP filter.

    Examples:
        >>> escape_ldap_filter("user*name")
        'user\\2aname'
        >>> escape_ldap_filter("a(b)c")
        'a\\28b\\29c'
    """
    if not isinstance(value, str):
        raise InputValidationError(f"Expected string value, got {type(value).__name__}")

    # Build escaped string by replacing each metacharacter
    escaped = []
    for char in value:
        if char in LDAP_FILTER_METACHARS:
            escaped.append(LDAP_FILTER_METACHARS[char])
        else:
            escaped.append(char)
    return "".join(escaped)


def validate_username(username: str) -> str:
    """
    Validate username against a strict allowlist pattern.

    Only alphanumeric characters, dots, hyphens, and underscores are allowed.
    This provides defense-in-depth: even if escaping is bypassed somehow,
    the allowlist prevents injection of LDAP filter syntax.

    Args:
        username: The raw username string from user input.

    Returns:
        The validated username string.

    Raises:
        InputValidationError: If the username fails validation.
    """
    if username is None:
        raise InputValidationError("Username must not be None")

    if not isinstance(username, str):
        raise InputValidationError(
            f"Username must be a string, got {type(username).__name__}"
        )

    # Strip whitespace but do not allow empty after strip
    username = username.strip()

    if not username:
        raise InputValidationError("Username must not be empty")

    if len(username) > 128:
        raise InputValidationError("Username exceeds maximum length of 128 characters")

    if not USERNAME_ALLOWLIST.match(username):
        raise InputValidationError(
            "Username contains invalid characters. "
            "Only alphanumeric, dot (.), hyphen (-), and underscore (_) are allowed."
        )

    return username


def validate_password(password: str) -> str:
    """
    Validate password to prevent anonymous bind bypass.

    An empty or None password in LDAP can trigger an anonymous bind, which
    succeeds without verifying credentials. This function explicitly rejects
    empty/None passwords.

    Args:
        password: The raw password string from user input.

    Returns:
        The validated password string.

    Raises:
        InputValidationError: If the password fails validation.
    """
    if password is None:
        raise InputValidationError("Password must not be None (prevents anonymous bind)")

    if not isinstance(password, str):
        raise InputValidationError(
            f"Password must be a string, got {type(password).__name__}"
        )

    # Critical: reject empty password to prevent anonymous bind bypass
    if len(password) < MIN_PASSWORD_LENGTH:
        raise InputValidationError(
            "Password must not be empty — empty passwords trigger anonymous bind"
        )

    if len(password) > MAX_PASSWORD_LENGTH:
        raise InputValidationError(
            f"Password exceeds maximum length of {MAX_PASSWORD_LENGTH} characters"
        )

    # Reject passwords that are only whitespace (could indicate missing input)
    if not password.strip():
        raise InputValidationError(
            "Password must not be only whitespace"
        )

    return password


# ---------------------------------------------------------------------------
# Secure LDAP Filter Builder
# ---------------------------------------------------------------------------

class LDAPFilterBuilder:
    """
    Structured builder for LDAP search filters that ensures all user-supplied
    values are properly escaped before being embedded.

    This replaces raw string concatenation patterns like:
        BAD:  filter = f"(uid={username})"
        GOOD: filter = LDAPFilterBuilder.equal("uid", username)
    """

    @staticmethod
    def equal(attribute: str, value: str) -> str:
        """Build an equality filter: (attribute=escaped_value)"""
        LDAPFilterBuilder._validate_attribute(attribute)
        escaped = escape_ldap_filter(value)
        return f"({attribute}={escaped})"

    @staticmethod
    def and_(filters: list) -> str:
        """Combine filters with AND: (&(filter1)(filter2)...)"""
        if not filters:
            raise ValueError("Cannot create AND filter with empty filter list")
        return "(&" + "".join(filters) + ")"

    @staticmethod
    def or_(filters: list) -> str:
        """Combine filters with OR: (|(filter1)(filter2)...)"""
        if not filters:
            raise ValueError("Cannot create OR filter with empty filter list")
        return "(|" + "".join(filters) + ")"

    @staticmethod
    def _validate_attribute(attribute: str) -> None:
        """Ensure attribute name contains only safe characters."""
        if not isinstance(attribute, str) or not attribute:
            raise ValueError("LDAP attribute name must be a non-empty string")
        # Attribute names should only contain alphanumeric and hyphen
        if not re.match(r"^[a-zA-Z0-9-]+$", attribute):
            raise ValueError(
                f"Invalid LDAP attribute name: {attribute!r}. "
                "Only alphanumeric and hyphen characters are allowed."
            )


# ---------------------------------------------------------------------------
# Secure LDAP Authentication
# ---------------------------------------------------------------------------

def authenticate_user(
    ldap_server_url: str,
    username: str,
    password: str,
    search_base: str,
    uid_attribute: str = "uid",
    use_ssl: bool = True,
    require_cert: bool = False,
    connect_timeout: int = 10,
    receive_timeout: int = 10,
) -> Tuple[bool, Optional[Dict[str, Any]]]:
    """
    Securely authenticate a user against an LDAP directory.

    This function implements the following security measures:
    1. Input validation via allowlist (validate_username)
    2. Empty password rejection (validate_password) — prevents anonymous bind
    3. RFC 4515-compliant filter escaping (escape_ldap_filter / LDAPFilterBuilder)
    4. TLS/SSL for transport security
    5. Post-bind verification to ensure the bind was authenticated

    Args:
        ldap_server_url: LDAP server URL (e.g., "ldaps://ldap.example.com:636")
        username: User's login name (will be validated and escaped).
        password: User's password (must be non-empty).
        search_base: Base DN for the LDAP search (e.g., "ou=users,dc=example,dc=com")
        uid_attribute: The attribute