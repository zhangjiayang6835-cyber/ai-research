"""LDAP authentication filter guard for issue #87.

LDAP injection happens when untrusted credentials are concatenated into filter
syntax such as ``(&(uid={username})(userPassword={password}))``. Attackers can
then inject wildcards, boolean clauses, or parentheses to bypass authentication.

This module keeps authentication as a two-step process: build an escaped lookup
filter for a constrained username, require exactly one account DN, and verify the
password through a bind/check callback instead of embedding the password in LDAP
filter syntax.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Callable, Iterable, Mapping


USERNAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._@-]{0,127}$")
ALLOWED_ACCOUNT_STATES = {"active", "enabled"}


class LDAPAuthError(ValueError):
    """Raised when authentication input or lookup results violate policy."""


@dataclass(frozen=True)
class LDAPAccount:
    dn: str
    attributes: Mapping[str, object]


def escape_ldap_filter_value(value: object) -> str:
    """Escape a value for use inside an LDAP filter assertion."""

    if not isinstance(value, str):
        raise LDAPAuthError("LDAP filter values must be text")
    escaped: list[str] = []
    for char in value:
        if char == "*":
            escaped.append(r"\2a")
        elif char == "(":
            escaped.append(r"\28")
        elif char == ")":
            escaped.append(r"\29")
        elif char == "\\":
            escaped.append(r"\5c")
        elif char == "\x00":
            escaped.append(r"\00")
        else:
            escaped.append(char)
    return "".join(escaped)


def build_user_lookup_filter(username: str, *, uid_attribute: str = "uid") -> str:
    """Build a safe account lookup filter for an authentication request."""

    if not isinstance(uid_attribute, str) or not re.fullmatch(r"[A-Za-z][A-Za-z0-9-]{0,31}", uid_attribute):
        raise LDAPAuthError("uid attribute must be a safe schema attribute")
    if not isinstance(username, str) or not USERNAME_RE.fullmatch(username):
        raise LDAPAuthError("username contains unsafe LDAP filter syntax")
    safe_username = escape_ldap_filter_value(username)
    return f"(&({uid_attribute}={safe_username})(objectClass=person)(accountStatus=active))"


def authenticate_user(
    username: str,
    password: str,
    search_accounts: Callable[[str], Iterable[LDAPAccount]],
    verify_password: Callable[[str, str], bool],
) -> LDAPAccount:
    """Authenticate without placing the password inside an LDAP filter."""

    if not isinstance(password, str) or not password:
        raise LDAPAuthError("password is required")
    user_filter = build_user_lookup_filter(username)
    accounts = list(search_accounts(user_filter))
    if len(accounts) != 1:
        raise LDAPAuthError("authentication requires exactly one account match")
    account = accounts[0]
    if not isinstance(account.dn, str) or not account.dn:
        raise LDAPAuthError("account DN is invalid")
    state = str(account.attributes.get("accountStatus", "")).lower()
    if state not in ALLOWED_ACCOUNT_STATES:
        raise LDAPAuthError("account is not active")
    if not verify_password(account.dn, password):
        raise LDAPAuthError("invalid credentials")
    return account


__all__ = ["LDAPAccount", "LDAPAuthError", "authenticate_user", "build_user_lookup_filter", "escape_ldap_filter_value"]
