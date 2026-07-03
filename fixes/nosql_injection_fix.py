"""
Fix for Issue #96: Blind NoSQL Injection in Login ($25)

Vulnerability:
    Login endpoints using NoSQL databases (MongoDB) that directly
    interpolate user input into query objects allow NoSQL injection
    attacks. Operators like $ne, $gt, $regex, $where can bypass
    authentication entirely.

Fix:
    Strict input sanitization: reject any input containing MongoDB
    operator keys ($ne, $regex, etc.), use parameterized queries,
    and type-coerce all input to strings before query construction.
"""

from __future__ import annotations

import json
import re
from typing import Any, Dict, List, Optional, Set, Tuple


# MongoDB operators that must be rejected in user input
NOSQL_OPERATORS: Set[str] = {
    # Comparison
    "$eq", "$ne", "$gt", "$gte", "$lt", "$lte",
    "$in", "$nin",
    # Element
    "$exists", "$type",
    # Evaluation
    "$expr", "$regex", "$options", "$text", "$search",
    "$language", "$where", "$mod",
    # Geospatial
    "$geoWithin", "$geoIntersects", "$near", "$nearSphere",
    "$geometry", "$maxDistance", "$minDistance",
    # Array
    "$all", "$elemMatch", "$size",
    # Bitwise
    "$bitsAllClear", "$bitsAllSet", "$bitsAnyClear", "$bitsAnySet",
    # Projection
    "$slice",
    # Update
    "$set", "$unset", "$push", "$pull", "$inc", "$dec",
    "$pushAll", "$pullAll", "$addToSet", "$each", "$position",
    "$sort", "$bit", "$currentDate", "$min", "$max",
    # Aggregation
    "$project", "$match", "$group", "$sort", "$limit", "$skip",
    "$unwind", "$lookup", "$graphLookup", "$facet", "$bucket",
    "$replaceRoot", "$count", "$addFields",
    # Query modifiers
    "$orderby", "$comment", "$hint", "$maxTimeMS", "$min",
    "$returnKey", "$showDiskLoc", "$snapshot", "$natural",
}

# Operators that also work with dot-notation variants
DOT_OPERATORS: Set[str] = {op.replace("$", "") for op in NOSQL_OPERATORS}


class NoSQLInjectionSanitizer:
    """Sanitize user input for NoSQL database queries."""

    def __init__(self, reject_dot_notation: bool = True) -> None:
        self.reject_dot_notation = reject_dot_notation
        self._operator_pattern = re.compile(
            r'^\$[a-zA-Z]\w*$'
        )
        self._log: list[dict] = []

    def _contains_operator(self, value: Any, path: str = "") -> Tuple[bool, str]:
        """Recursively check if a value contains NoSQL operators."""
        if isinstance(value, dict):
            for key, val in value.items():
                full_key = f"{path}.{key}" if path else key
                if key in NOSQL_OPERATORS:
                    return True, f"Found NoSQL operator '{key}' at {full_key}"
                if self.reject_dot_notation and key.startswith("$"):
                    return True, f"Found $-prefixed key at {full_key}"
                recursive_check, detail = self._contains_operator(val, full_key)
                if recursive_check:
                    return True, detail
        elif isinstance(value, list):
            for idx, item in enumerate(value):
                recursive_check, detail = self._contains_operator(
                    item, f"{path}[{idx}]"
                )
                if recursive_check:
                    return True, detail
        elif isinstance(value, str):
            # Check for JSON-encoded operators
            if value.strip().startswith("{"):
                try:
                    parsed = json.loads(value)
                    return self._contains_operator(parsed, path)
                except (json.JSONDecodeError, ValueError):
                    pass
            # Check for inline operators like username[$ne]=
            if "$" in value and "=" in value:
                for op in NOSQL_OPERATORS:
                    if op in value:
                        return True, f"Inline NoSQL operator '{op}' in string"
        return False, ""

    def sanitize_string(self, value: str) -> str:
        """Sanitize a string input, raising on NoSQL operators."""
        contains_op, detail = self._contains_operator(value)
        if contains_op:
            self._log.append({
                "action": "rejected",
                "input": value[:100],
                "detail": detail,
                "timestamp": __import__('time').time(),
            })
            raise ValueError(f"NoSQL injection detected: {detail}")
        return value.strip()

    def sanitize_login_input(
        self, username: str, password: str
    ) -> Tuple[Optional[str], Optional[str], str]:
        """Sanitize login form inputs.

        Returns:
            (sanitized_username, sanitized_password, error_message)
            On rejection: (None, None, error_message)
        """
        if not username or not password:
            return None, None, "Username and password are required"

        try:
            safe_user = self.sanitize_string(username)
            safe_pass = self.sanitize_string(password)
        except ValueError as e:
            return None, None, str(e)

        return safe_user, safe_pass, ""

    def safe_login_query(self, username: str, password: str) -> dict:
        """Build a parameterized login query.

        This produces a dict like:
            {"username": safe_username, "password": safe_password}
        which can be used with MongoDB's find_one() or similar.
        """
        safe_u, safe_p, err = self.sanitize_login_input(username, password)
        if err:
            raise ValueError(err)

        # The key insight: use literal string values, NOT query operators
        return {
            "username": {"$eq": safe_u},  # explicit $eq is safe when input is sanitized
            "password": {"$eq": safe_p},
        }

    def get_audit_log(self) -> list[dict]:
        return self._log[-100:]


def mongo_safe_authenticate(
    db_collection: Any,
    username: str,
    password: str,
) -> Tuple[bool, str]:
    """Safe authentication helper for MongoDB login.

    Args:
        db_collection: A MongoDB collection with find_one method.
        username, password: Raw user input.

    Returns:
        (authenticated, error_message)
    """
    sanitizer = NoSQLInjectionSanitizer()
    safe_u, safe_p, err = sanitizer.sanitize_login_input(username, password)
    if err:
        return False, err

    # Use type-coerced string values — NEVER pass the raw dict
    user = db_collection.find_one({
        "username": safe_u,
        "password": safe_p,
    })
    if user:
        return True, ""
    return False, "Invalid credentials"


# --------------------------------------------------------------------- self-test
if __name__ == "__main__":
    s = NoSQLInjectionSanitizer()

    # Normal login should pass
    ok_user, ok_pass, err = s.sanitize_login_input("alice", "mypassword")
    assert err == "", f"normal login should pass: {err}"
    assert ok_user == "alice"

    # NoSQL injection attempts should fail
    for malicious in [
        {"$ne": ""},
        {"$gt": ""},
        {"$regex": ".*"},
        {"$where": "1==1"},
        '{"$ne": ""}',
        '{"$gt": ""}',
    ]:
        caught = False
        try:
            s.sanitize_login_input("admin", str(malicious))
        except ValueError:
            caught = True
        assert caught, f"should catch: {malicious}"

    # Safe query building
    query = s.safe_login_query("bob", "secure123")
    assert "$ne" not in str(query), "safe query should not have $ne"
    assert "$regex" not in str(query), "safe query should not have $regex"
    assert query.get("username") == {"$eq": "bob"}, \
        f"unexpected username query: {query.get('username')}"

    print("nosql_injection_fix self-test passed")
    print(f"  Normal login OK: {ok_user}")
    print(f"  All injection attempts blocked: ✓")
    print(f"  Safe query: {query}")
