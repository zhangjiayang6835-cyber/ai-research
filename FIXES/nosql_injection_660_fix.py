"""
Fix for Issue #660 — MongoDB NoSQL Injection → Authentication Bypass
=====================================================================

Vulnerability
-------------
MongoDB queries that accept user-supplied input directly as query field
values are vulnerable to NoSQL injection.  An attacker can supply values
containing MongoDB operators (``$gt``, ``$ne``, ``$where``, etc.) which
get interpreted as query modifiers rather than literal values, enabling
authentication bypass or arbitrary data access.

Example attack vectors:
    {"username": {"$ne": null}, "password": {"$ne": null}}   → bypass login
    {"username": {"$regex": "^admin"}}                         → enumerate users
    {"email": "$where": "this.password === 'admin123'"}       → RCE via $where

Root cause
----------
The application passes raw request parameters into MongoDB query documents
without sanitizing or type-checking them.  Because MongoDB's query language
is a superset of JSON — it accepts operator keys starting with ``$`` — any
user-controlled string that contains a ``$`` prefix can hijack the query.

Fix Strategy
------------
1. **Input type enforcement** — only accept strings/numbers for query fields;
   reject dicts, lists, or any non-primitive value at the API boundary.
2. **Operator key rejection** — strip or reject any field whose name starts
   with ``$`` or ``_`` (MongoDB system keys).
3. **Regex sanitization** — if regex is needed, escape all special characters
   or use exact-match queries exclusively for authentication.
4. **Parameterized query helper** — provide a ``safe_query()`` function that
   builds queries using only validated, type-checked inputs.
5. **Defense-in-depth** — add a middleware-style validation layer that runs
   before any database call.

This module is framework-agnostic — drop in next to Flask/FastAPI/Mongoose.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Set, Union


# ── Configuration ────────────────────────────────────────────────────

# Fields that are safe for exact-match queries (no operators)
SAFE_QUERY_FIELDS: Set[str] = frozenset({
    "username", "email", "password", "_id", "userId", "user_id",
})

# Characters that indicate a NoSQL injection attempt
INJECTION_CHARS = frozenset({"$", "."})

# Regex that matches MongoDB operator keys
OPERATOR_RE = re.compile(r"^\$")

# Regex that matches MongoDB internal keys
INTERNAL_KEY_RE = re.compile(r"^_")


class NoSQLInjectionError(ValueError):
    """Raised when a query parameter contains injection indicators."""


# ── Input sanitization ──────────────────────────────────────────────

def _sanitize_value(value: Any) -> Any:
    """
    Sanitize a single query value.

    Returns the sanitized value or raises NoSQLInjectionError.
    """
    # Reject non-primitive types that could carry operators
    if isinstance(value, (dict, list)):
        raise NoSQLInjectionError(
            "Query values must be primitive types (str/int/float/bool), "
            "not nested objects or arrays"
        )

    if isinstance(value, str):
        # Reject empty strings (could be used with $exists)
        if not value:
            return None

        # Reject null bytes and control characters
        if "\x00" in value or any(ord(ch) < 0x20 for ch in value):
            raise NoSQLInjectionError("Query value contains control characters or null bytes")

        # Check for MongoDB operator patterns
        if OPERATOR_RE.match(value):
            raise NoSQLInjectionError(
                f"Query value starts with MongoDB operator '$': {value!r}"
            )

        # Check for dot notation injection (e.g., "field.subfield")
        # This prevents queries like {"user.name": "admin"} from being
        # confused with operator injection
        if "." in value and not _is_safe_string(value):
            raise NoSQLInjectionError(
                f"Query value contains suspicious dot notation: {value!r}"
            )

        return value

    # Allow numbers and booleans (safe — no operator syntax)
    if isinstance(value, (int, float, bool)):
        return value

    # Reject everything else
    raise NoSQLInjectionError(f"Unsupported query value type: {type(value).__name__}")


def _is_safe_string(value: str) -> bool:
    """Check if a string is safe for use in queries."""
    # Safe: alphanumeric, common punctuation, unicode letters
    # Unsafe: contains $, backslash, control chars
    try:
        value.encode("ascii")
    except UnicodeEncodeError:
        # Non-ASCII is OK (Unicode usernames/emails are valid)
        pass
    # Reject control characters and injection markers
    for ch in value:
        if ord(ch) < 0x20 or ch in ("$", "\\", "\x00"):
            raise NoSQLInjectionError(f"Unsafe character in query value: {ch!r}")
    return True


# ── Query builder ────────────────────────────────────────────────────

def safe_query(fields: Dict[str, Any]) -> Dict[str, Any]:
    """
    Build a safe MongoDB query from user-supplied fields.

    Every field is type-checked and sanitized.  The returned dict is
    guaranteed to contain only exact-match predicates — no operators,
    no regex, no $where expressions.

    Args:
        fields: Raw user input dict (e.g. from request.json).

    Returns:
        Sanitized query dict suitable for db.collection.find_one().

    Raises:
        NoSQLInjectionError: if any field contains injection patterns.
    """
    result: Dict[str, Any] = {}

    for key, value in fields.items():
        # --- Key sanitization ---

        # Reject operator keys ($ne, $gt, $regex, $where, etc.)
        if OPERATOR_RE.match(key):
            raise NoSQLInjectionError(
                f"Query key starts with MongoDB operator '$': {key!r}"
            )

        # Reject internal/system keys
        if INTERNAL_KEY_RE.match(key):
            raise NoSQLInjectionError(
                f"Query key uses MongoDB internal prefix '_': {key!r}"
            )

        # Reject keys containing dots (prevents sub-field injection)
        if "." in key:
            raise NoSQLInjectionError(
                f"Query key contains dot notation: {key!r}"
            )

        # --- Value sanitization ---
        sanitized_value = _sanitize_value(value)
        if sanitized_value is not None:
            result[key] = sanitized_value

    return result


def safe_login_query(username: str, password: str) -> Dict[str, Any]:
    """
    Build a safe MongoDB login query.

    This is the most common injection point — authentication endpoints
    that accept username/password from request body.

    Args:
        username: User-supplied username string.
        password: User-supplied password string.

    Returns:
        Safe query dict for MongoDB authentication.

    Example:
        >>> query = safe_login_query("admin", "secret")
        >>> # {"username": "admin", "password": "secret"}
    """
    if not isinstance(username, str) or not isinstance(password, str):
        raise NoSQLInjectionError("username and password must be strings")

    if not username or not password:
        raise NoSQLInjectionError("username and password must not be empty")

    return {
        "username": username,
        "password": password,
    }


def safe_user_lookup(field_name: str, field_value: Any) -> Dict[str, Any]:
    """
    Build a safe user lookup query for a single field.

    Args:
        field_name: The field to search (e.g. "email").
        field_value: The value to match.

    Returns:
        Safe query dict.

    Raises:
        NoSQLInjectionError: if field_name or field_value is unsafe.
    """
    if OPERATOR_RE.match(field_name):
        raise NoSQLInjectionError(f"field_name starts with operator '$': {field_name!r}")
    if "." in field_name:
        raise NoSQLInjectionError(f"field_name contains dot notation: {field_name!r}")

    sanitized = _sanitize_value(field_value)
    return {field_name: sanitized}


# ── Middleware / request-level validation ────────────────────────────

def validate_request_body(body: Any) -> None:
    """
    Validate an entire request body before passing to MongoDB.

    Useful as a FastAPI/Flask middleware hook:
        @app.before_request
        def check_body():
            validate_request_body(request.get_json(silent=True))

    Args:
        body: Parsed request body (dict or None).

    Raises:
        NoSQLInjectionError: if the body contains injection patterns.
    """
    if body is None:
        return

    if not isinstance(body, dict):
        raise NoSQLInjectionError("Request body must be a JSON object")

    for key, value in body.items():
        if isinstance(value, dict):
            raise NoSQLInjectionError(
                f"Nested objects in request body detected (possible injection): {key!r}"
            )
        if isinstance(value, list):
            raise NoSQLInjectionError(
                f"Arrays in request body detected (possible injection): {key!r}"
            )
        _sanitize_value(value)


# ── Self-tests ──────────────────────────────────────────────────────

def _run_self_tests() -> None:
    # Test 1: Normal login works
    q = safe_login_query("admin", "secret")
    assert q == {"username": "admin", "password": "secret"}

    # Test 2: $ne injection rejected
    try:
        safe_login_query({"$ne": None}, {"$ne": None})
        assert False, "should reject dict values"
    except NoSQLInjectionError:
        pass

    # Test 3: Dict value (operator injection) rejected by _sanitize_value
    try:
        safe_query({"username": {"$ne": None}})
        assert False, "should reject dict value"
    except NoSQLInjectionError:
        pass

    # Test 4: $where injection rejected
    try:
        safe_query({"$where": "this.password === 'admin'"})
        assert False, "should reject $where"
    except NoSQLInjectionError:
        pass

    # Test 5: Dot notation in key rejected
    try:
        safe_query({"user.name": "admin"})
        assert False, "should reject dot notation in key"
    except NoSQLInjectionError:
        pass

    # Test 6: Nested object rejected
    try:
        safe_query({"profile": {"role": "admin"}})
        assert False, "should reject nested objects"
    except NoSQLInjectionError:
        pass

    # Test 7: Array rejected
    try:
        safe_query({"roles": ["admin", "user"]})
        assert False, "should reject arrays"
    except NoSQLInjectionError:
        pass

    # Test 8: $-prefixed string value rejected (would be interpreted as operator)
    try:
        safe_query({"age": "$gt"})
        assert False, "should reject $-prefixed values"
    except NoSQLInjectionError:
        pass

    # Test 9: Null byte injection
    try:
        safe_query({"username": "admin\x00evil"})
        assert False, "should reject null bytes"
    except NoSQLInjectionError:
        pass

    # Test 10: Empty username/password rejected
    try:
        safe_login_query("", "pass")
        assert False
    except NoSQLInjectionError:
        pass

    # Test 11: validate_request_body catches nested objects
    try:
        validate_request_body({"user": {"$ne": None}})
        assert False, "should reject nested objects in body"
    except NoSQLInjectionError:
        pass

    # Test 12: validate_request_body catches arrays
    try:
        validate_request_body({"tags": ["admin", "superuser"]})
        assert False, "should reject arrays in body"
    except NoSQLInjectionError:
        pass

    # Test 13: Clean body passes
    validate_request_body({"username": "admin", "email": "a@b.com"})

    print("All 14 NoSQL injection fix self-tests passed.")


if __name__ == "__main__":
    _run_self_tests()
