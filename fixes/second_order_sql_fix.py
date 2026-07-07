"""
Fix: Second-Order SQL Injection in Stored Procedure Chain
==========================================================
Issue #340 — Second-order SQL injection occurs when data is
safely stored but later retrieved and unsafely concatenated
into SQL queries. Attackers inject malicious payloads into
stored data fields that are later used in dynamic SQL.

This fix provides:
1. Parameterized queries for all stored procedure calls
2. Input validation for data that will be re-queried
3. Stored procedure output sanitization
"""

from __future__ import annotations

import re
from typing import Any, Optional
from dataclasses import dataclass


# ═══════════════════════════════════════════════════════════════════
# Configuration
# ═══════════════════════════════════════════════════════════════════

# SQL keywords that should never appear in stored data used in queries
SQL_META_CHARS = re.compile(
    r"""['\"\-\-;]|\b(SELECT|INSERT|UPDATE|DELETE|DROP|UNION|
    EXEC|EXECUTE|ALTER|CREATE|TRUNCATE|OR\s+1=1|
    SLEEP|BENCHMARK|pg_sleep|WAITFOR|xp_cmdshell)\b""",
    re.IGNORECASE | re.VERBOSE,
)


# ═══════════════════════════════════════════════════════════════════
# Custom Error
# ═══════════════════════════════════════════════════════════════════


class SecondOrderSQLInjectionError(ValueError):
    """Raised when second-order SQL injection indicators are detected."""


# ═══════════════════════════════════════════════════════════════════
# PART 1: SAFE STORED PROCEDURE EXECUTION
# ═══════════════════════════════════════════════════════════════════


class SafeStoredProcedure:
    """Safe stored procedure executor with parameterized queries.

    Uses parameterized queries via bind variables ($1, $2, etc.)
    instead of string concatenation, which prevents both first-order
    and second-order SQL injection.
    """

    @staticmethod
    def execute_safe(
        procedure_name: str,
        params: dict[str, Any],
        param_order: list[str],
    ) -> str:
        """Build a parameterized stored procedure call.

        Args:
            procedure_name: Name of the stored procedure.
            params: Dict of parameter names to values.
            param_order: Ordered list of parameter names.

        Returns:
            A parameterized SQL string.

        Example:
            >>> SafeStoredProcedure.execute_safe(
            ...     "get_user_by_email",
            ...     {"user_email": "test@example.com"},
            ...     ["user_email"],
            ... )
            'CALL get_user_by_email($1)'
        """
        placeholders = [
            f"${i + 1}"
            for i in range(len(param_order))
        ]
        return f"CALL {procedure_name}({', '.join(placeholders)})"

    @staticmethod
    def sanitize_output_value(value: str) -> str:
        """Sanitize a value retrieved from a stored procedure.

        Second-order SQL injection often happens when stored
        procedure output is later concatenated into SQL. This
        method escapes dangerous characters.

        Args:
            value: String value from SP output.

        Returns:
            Escaped string safe for SQL context.
        """
        if not isinstance(value, str):
            return value
        # Escape single quotes (double them for SQL)
        escaped = value.replace("'", "''")
        # Remove control characters
        escaped = re.sub(r"[\x00-\x08\x0B\x0C\x0E-\x1F]", "", escaped)
        return escaped


# ═══════════════════════════════════════════════════════════════════
# PART 2: INPUT VALIDATION FOR SECOND-ORDER PROTECTION
# ═══════════════════════════════════════════════════════════════════


class SecondOrderInputValidator:
    """Validates input that could be used in second-order SQL injection.

    Validates data BEFORE it's stored, ensuring it won't cause
    injection when later retrieved and used in queries.
    """

    @staticmethod
    def validate_for_sql_safety(value: str) -> str:
        """Validate and sanitize a value before storage.

        Args:
            value: Input value to validate.

        Returns:
            Sanitized value safe for storage and later SQL use.

        Raises:
            SecondOrderSQLInjectionError: If SQL injection detected.
        """
        if not isinstance(value, str):
            return str(value) if value is not None else ""

        # Check for SQL metacharacters
        match = SQL_META_CHARS.search(value)
        if match:
            raise SecondOrderSQLInjectionError(
                f"Potential second-order SQL injection detected: "
                f"found '{match.group()}' in input"
            )

        # Escape single quotes
        sanitized = value.replace("'", "''")
        return sanitized

    @staticmethod
    def validate_and_strip(value: str, max_length: int = 1000) -> str:
        """Validate, sanitize, and truncate a value for safe storage.

        Args:
            value: Input value.
            max_length: Maximum allowed length.

        Returns:
            Safe, truncated value.
        """
        # Check for SQL patterns
        try:
            value = SecondOrderInputValidator.validate_for_sql_safety(value)
        except SecondOrderSQLInjectionError:
            # Strip dangerous content rather than rejecting entirely
            value = SQL_META_CHARS.sub("", value)

        # Truncate to prevent oversized stored values
        if len(value) > max_length:
            value = value[:max_length]

        return value


# ═══════════════════════════════════════════════════════════════════
# PART 3: APPLICATION-LEVEL DEFENSE
# ═══════════════════════════════════════════════════════════════════


@dataclass
class QueryResult:
    """Safe query result wrapper."""
    success: bool
    data: Any = None
    error: Optional[str] = None


class ApplicationSQLGuard:
    """Application-level SQL injection guard for stored procedures.

    Wraps all stored procedure calls with safety checks
    to prevent first and second-order SQL injection.
    """

    def __init__(self):
        self.validator = SecondOrderInputValidator()
        self.sproc = SafeStoredProcedure()

    def store_user_input(
        self,
        field_name: str,
        user_value: str,
    ) -> QueryResult:
        """Safely store user input that could later be re-queried.

        Args:
            field_name: Database column name.
            user_value: Raw user input.

        Returns:
            QueryResult with sanitized data.
        """
        try:
            safe_value = self.validator.validate_and_strip(user_value)
            sql = self.sproc.execute_safe(
                "insert_audit_trail",
                {"field": field_name, "value": safe_value},
                ["field", "value"],
            )
            return QueryResult(success=True, data={
                "sql": sql,
                "params": [field_name, safe_value],
                "sanitized_value": safe_value,
            })
        except Exception as e:
            return QueryResult(success=False, error=str(e))

    def query_stored_data(
        self,
        procedure_name: str,
        param_name: str,
        param_value: str,
    ) -> QueryResult:
        """Safely query using previously stored data.

        This is where second-order injection would occur.
        The fix ensures parameterized queries are always used.

        Args:
            procedure_name: Stored procedure name.
            param_name: Parameter name.
            param_value: Value (possibly from stored data).

        Returns:
            QueryResult with safe query structure.
        """
        # Even if param_value contains SQL, it can't escape
        # because we use parameterized queries
        safe_value = SafeStoredProcedure.sanitize_output_value(param_value)
        sql = self.sproc.execute_safe(
            procedure_name,
            {param_name: safe_value},
            [param_name],
        )
        return QueryResult(success=True, data={
            "sql": sql,
            "params": [safe_value],
        })


# ═══════════════════════════════════════════════════════════════════
# Before / After example
# ═══════════════════════════════════════════════════════════════════

# B E F O R E  (vulnerable):
#
#   # User submits a profile bio containing SQL
#   bio = "I love ' OR '1'='1"
#   # Stored safely (first-order prevented by ORM)
#   db.execute("INSERT INTO profiles (bio) VALUES ('" + escape(bio) + "')")
#   # ✅ Stored as literal text — no immediate injection
#
#   # Later, an admin runs a report:
#   report_sql = "SELECT * FROM users WHERE bio = '" + stored_bio + "'"
#   # ❌ Second-order injection! The stored data now executes as SQL!
#   # SELECT * FROM users WHERE bio = 'I love ' OR '1'='1'
#   # Returns ALL users!

# A F T E R  (fixed):
#
#   from fixes.second_order_sql_fix import (
#       SecondOrderInputValidator,
#       SafeStoredProcedure,
#   )
#
#   # When storing:
#   safe_bio = SecondOrderInputValidator.validate_and_strip(bio)
#   db.execute("INSERT INTO profiles (bio) VALUES ($1)", [safe_bio])
#
#   # When querying:
#   sql = SafeStoredProcedure.execute_safe(
#       "search_by_bio", {"bio": stored_bio}, ["bio"]
#   )
#   # → "CALL search_by_bio($1)" — parameterized, not concatenated!
#   db.execute(sql, [stored_bio])


# ═══════════════════════════════════════════════════════════════════
# Self-test
# ═══════════════════════════════════════════════════════════════════


def _test() -> None:
    print("  Testing Second-Order SQL Injection fix...")

    # ── Parameterized query generation ──
    sql = SafeStoredProcedure.execute_safe(
        "get_user",
        {"user_id": 123, "email": "test@x.com"},
        ["user_id", "email"],
    )
    assert sql == "CALL get_user($1, $2)", f"Unexpected: {sql}"
    print("  ✓ Parameterized query generated correctly")

    # ── Second-order input detection ──
    validator = SecondOrderInputValidator()
    try:
        validator.validate_for_sql_safety("Robert'; DROP TABLE Students;--")
        assert False, "Should have detected SQL injection!"
    except SecondOrderSQLInjectionError:
        pass
    print("  ✓ Basic SQL injection detected in stored data")

    try:
        validator.validate_for_sql_safety("hello OR 1=1")
        assert False, "Should have detected!"
    except SecondOrderSQLInjectionError:
        pass
    print("  ✓ OR 1=1 pattern detected")

    # ── Safe strings pass through ──
    result = validator.validate_and_strip("Hello, this is safe text!")
    assert "'" not in result
    print("  ✓ Safe text passes validation")

    # ── Truncation works ──
    long_text = "A" * 2000
    result = validator.validate_and_strip(long_text, max_length=100)
    assert len(result) == 100
    print("  ✓ Overlong input truncated correctly")

    # ── Output sanitization ──
    escaped = SafeStoredProcedure.sanitize_output_value("O'Brien")
    assert escaped == "O''Brien", f"Unexpected: {escaped}"
    print("  ✓ Output sanitization escapes single quotes")

    # ── Application guard ──
    guard = ApplicationSQLGuard()
    result = guard.store_user_input("bio", "Hello World")
    assert result.success
    print("  ✓ Application guard stores safely")

    result = guard.query_stored_data(
        "search_users", "bio", "Hello'; DROP TABLE users;--"
    )
    assert result.success
    assert "$1" in result.data["sql"]
    print("  ✓ Application guard queries safely with parameters")

    print("\n  ✓ ALL TESTS PASSED")


if __name__ == "__main__":
    _test()
