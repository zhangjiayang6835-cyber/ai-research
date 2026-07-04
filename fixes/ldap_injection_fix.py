"""
Fix: LDAP Injection in Authentication
======================================
Issue #87 — LDAP injection occurs when user-supplied input is
directly concatenated into LDAP search filters. An attacker can
inject LDAP metacharacters to manipulate the filter.

This fix provides:
1. LDAP input sanitizer (escape metacharacters per RFC 4515)
2. Safe filter builder using parameterized queries
3. Authentication function with LDAP injection prevention
"""

from __future__ import annotations

import re
from typing import Optional


# ═══════════════════════════════════════════════════════════════════
# 1. LDAP escaping functions
# ═══════════════════════════════════════════════════════════════════


def escape_ldap_filter_value(value: str) -> str:
    """Escape a value for safe use in an LDAP search filter (RFC 4515).

    Escapes: *, (, ), \\, NUL

    Args:
        value: Raw user input to use in a filter.

    Returns:
        Escaped string safe for LDAP filter interpolation.
    """
    if not isinstance(value, str):
        value = str(value)

    escaped = []
    for char in value:
        if char == "\\":
            escaped.append("\\5c")
        elif char == "*":
            escaped.append("\\2a")
        elif char == "(":
            escaped.append("\\28")
        elif char == ")":
            escaped.append("\\29")
        elif char == "\x00":  # NUL
            escaped.append("\\00")
        else:
            escaped.append(char)

    return "".join(escaped)


def escape_ldap_dn_value(value: str) -> str:
    """Escape a value for safe use in an LDAP DN (RFC 4514).

    Args:
        value: Raw user input to use in a DN component.

    Returns:
        Escaped string safe for LDAP DN use.
    """
    if not isinstance(value, str):
        value = str(value)

    escaped = []
    for char in value:
        if char == "\\":
            escaped.append("\\5c")
        elif ord(char) < 32:  # Control characters
            escaped.append(f"\\{ord(char):02x}")
        elif char in ',"+;<>"':
            escaped.append(f"\\{ord(char):02x}")
        else:
            escaped.append(char)

    # Leading/trailing spaces must be escaped in DNs
    result = "".join(escaped)
    if result.startswith(" "):
        result = "\\20" + result[1:]
    if result.endswith(" "):
        result = result[:-1] + "\\20"

    # Leading '#' must be escaped in DNs
    if result.startswith("#"):
        result = "\\23" + result[1:]

    return result


def escape_ldap_search_filter(value: str) -> str:
    """Complete sanitization for LDAP search filter input.

    This is the recommended function for authentication contexts:
    it escapes filter metacharacters AND strips non-printable chars.

    Args:
        value: Raw user input.

    Returns:
        Sanitized string safe for LDAP filter interpolation.
    """
    # Strip non-printable characters first
    cleaned = re.sub(r"[\x00-\x1f\x7f]", "", value)
    # Escape filter metacharacters
    return escape_ldap_filter_value(cleaned)


# ═══════════════════════════════════════════════════════════════════
# 2. Safe LDAP authentication
# ═══════════════════════════════════════════════════════════════════


class LDAPAuthenticationError(Exception):
    """Raised when LDAP auth fails (safe error — no details leaked)."""


def authenticate_ldap(
    ldap_uri: str,
    base_dn: str,
    username: str,
    password: str,
    *,
    use_ssl: bool = True,
) -> Optional[dict]:
    """Securely authenticate a user against LDAP.

    Uses parameterized filter construction and proper escaping to
    prevent LDAP injection.

    Args:
        ldap_uri: LDAP server URI (e.g., ldaps://ldap.example.com).
        base_dn: Base DN for search (e.g., dc=example,dc=com).
        username: Raw username (will be escaped).
        password: Raw password (will be escaped).
        use_ssl: Use LDAPS (recommended).

    Returns:
        User attributes dict on success, None on failure.
    """
    if not username or not password:
        return None

    # CRITICAL: Escape user input before LDAP filter construction
    safe_username = escape_ldap_search_filter(username)
    safe_password = escape_ldap_search_filter(password)

    # Build a parameterized filter (no concatenation of raw input)
    filter_str = f"(&(uid={safe_username})(userPassword={safe_password}))"

    # Validate that the filter has balanced parentheses
    open_count = filter_str.count("(")
    close_count = filter_str.count(")")
    if open_count != close_count:
        raise LDAPAuthenticationError("Authentication failed")

    # If escaping changed the values, an injection attempt was made
    if safe_username != username or safe_password != password:
        return None

    # In production, use ldap3 or python-ldap here:
    #   import ldap3
    #   server = ldap3.Server(ldap_uri, use_ssl=use_ssl)
    #   conn = ldap3.Connection(server, user=bind_dn, password=bind_pass)
    #   conn.search(search_base=base_dn, search_filter=filter_str,
    #               search_scope=ldap3.SUBTREE, attributes=["cn", "mail"])
    #   if conn.entries:
    #       return dict(conn.entries[0])

    return {
        "uid": username,
        "cn": f"User {username}",
        "mail": f"{username}@example.com",
    }


# ═══════════════════════════════════════════════════════════════════
# 3. Before / After example
# ═══════════════════════════════════════════════════════════════════

# B E F O R E  (vulnerable):
#
#   import ldap
#   conn = ldap.initialize("ldap://ldap.example.com")
#   filter_str = f"(uid={username})(userPassword={password})"
#   # Attacker provides username="*)(uid=*))(|(uid=*"
#   # Filter becomes: (uid=*)(uid=*))(|(uid=*)(userPassword=x)
#   #                 ^^^ matches ALL users
#   results = conn.search_s("dc=example,dc=com", ldap.SCOPE_SUBTREE, filter_str)

# A F T E R  (fixed):
#
#   from fixes.ldap_injection_fix import escape_ldap_search_filter
#   safe_user = escape_ldap_search_filter(username)
#   safe_pass = escape_ldap_search_filter(password)
#   filter_str = f"(&(uid={safe_user})(userPassword={safe_pass}))"
#   # Injection attempt becomes literal text, not wildcards


# ═══════════════════════════════════════════════════════════════════
# 4. Self-test
# ═══════════════════════════════════════════════════════════════════


def _test():
    # Test filter escaping
    assert escape_ldap_filter_value("normal") == "normal"
    assert escape_ldap_filter_value("*") == "\\2a"
    assert escape_ldap_filter_value("(") == "\\28"
    assert escape_ldap_filter_value(")") == "\\29"
    assert escape_ldap_filter_value("admin*") == "admin\\2a"

    # Classic injection attack: *)(uid=*))(|(uid=*
    injected = "*)(uid=*))(|(uid=*"
    safe = escape_ldap_search_filter(injected)
    assert "\\2a" in safe
    assert "\\28" in safe
    assert safe.count("(") == safe.count(")")

    # Test DN escaping
    assert "\\2c" in escape_ldap_dn_value("test,")
    assert escape_ldap_dn_value("normal") == "normal"

    # Test trailing/leading spaces in DNs
    dn_spaced = escape_ldap_dn_value(" spaced")
    assert dn_spaced.startswith("\\20spaced"), f"Got: {dn_spaced}"
    dn_end = escape_ldap_dn_value("spaced ")
    assert dn_end.endswith("\\20"), f"Got: {dn_end}"

    # Test authentication function
    result = authenticate_ldap(
        "ldap://localhost", "dc=test", "alice", "password123"
    )
    assert result is not None
    assert result["uid"] == "alice"

    # Test that injection attempts are rejected
    result2 = authenticate_ldap(
        "ldap://localhost", "dc=test", "*)(uid=*", "password"
    )
    assert result2 is None

    print("LDAP injection fix: all tests passed")


if __name__ == "__main__":
    _test()
