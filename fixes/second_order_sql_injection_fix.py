"""Fix pattern for issue #340: second-order SQL injection.

Second-order SQL injection happens when an application stores attacker input
"safely" during one request, then later concatenates the stored value into a
different SQL statement, report, scheduled job, or stored-procedure call. The
stored value becomes active SQL on the second use.

This module shows the safe pattern:

* persist user-controlled values only through DB-API bound parameters;
* retrieve saved values through tenant/user-scoped bound parameters;
* reuse saved values only as bound parameters, never through string
  interpolation;
* if a stored-procedure name must be dynamic, validate the identifier against a
  strict allow-list pattern and bind every argument.
"""

from __future__ import annotations

import re
import sqlite3
from collections.abc import Sequence
from typing import Any


MAX_STORED_VALUE_LENGTH = 256
_IDENTIFIER_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_SCALAR_TYPES = (str, int, float, bool, type(None))


class StoredSqlValueError(ValueError):
    """Raised when a stored value cannot be safely reused in SQL."""


def _validate_scalar(value: Any) -> Any:
    if not isinstance(value, _SCALAR_TYPES):
        raise StoredSqlValueError("SQL-bound values must be scalar")
    if isinstance(value, str) and len(value) > MAX_STORED_VALUE_LENGTH:
        raise StoredSqlValueError("SQL-bound string exceeds length limit")
    return value


def validate_identifier(identifier: str) -> str:
    """Return a safe SQL identifier or raise.

    SQL drivers cannot bind table, column, or procedure names as parameters.
    When one of those identifiers is dynamic, it must come from trusted code or
    pass a strict allow-list check. This function rejects separators, quotes,
    comments, whitespace, and dotted paths.
    """

    if not isinstance(identifier, str) or not _IDENTIFIER_RE.fullmatch(identifier):
        raise StoredSqlValueError("Unsafe SQL identifier")
    return identifier


def create_schema(conn: sqlite3.Connection) -> None:
    """Create demo tables used by the safe helper functions and tests."""

    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS saved_reports (
            report_id TEXT NOT NULL,
            owner_id TEXT NOT NULL,
            status_filter TEXT NOT NULL,
            PRIMARY KEY (report_id, owner_id)
        );

        CREATE TABLE IF NOT EXISTS orders (
            id INTEGER PRIMARY KEY,
            owner_id TEXT NOT NULL,
            status TEXT NOT NULL,
            total INTEGER NOT NULL
        );
        """
    )


def save_report_filter(
    conn: sqlite3.Connection,
    *,
    report_id: str,
    owner_id: str,
    status_filter: str,
) -> None:
    """Persist a saved report filter without concatenating attacker input."""

    conn.execute(
        """
        INSERT OR REPLACE INTO saved_reports (report_id, owner_id, status_filter)
        VALUES (?, ?, ?)
        """,
        (
            _validate_scalar(report_id),
            _validate_scalar(owner_id),
            _validate_scalar(status_filter),
        ),
    )


def fetch_orders_for_saved_report(
    conn: sqlite3.Connection,
    *,
    report_id: str,
    owner_id: str,
) -> list[tuple[int, str, int]]:
    """Use a saved filter safely in a second query.

    The stored ``status_filter`` might contain a payload such as
    ``paid' OR 1=1 --``. Because it is passed as a bound parameter in the
    second query, the database treats it as a literal value, not SQL syntax.
    """

    report = conn.execute(
        """
        SELECT status_filter
        FROM saved_reports
        WHERE report_id = ? AND owner_id = ?
        """,
        (_validate_scalar(report_id), _validate_scalar(owner_id)),
    ).fetchone()
    if report is None:
        return []

    status_filter = _validate_scalar(report[0])
    rows = conn.execute(
        """
        SELECT id, status, total
        FROM orders
        WHERE owner_id = ? AND status = ?
        ORDER BY id
        """,
        (_validate_scalar(owner_id), status_filter),
    ).fetchall()
    return [(int(row[0]), str(row[1]), int(row[2])) for row in rows]


def build_safe_procedure_call(
    procedure_name: str,
    args: Sequence[Any],
) -> tuple[str, tuple[Any, ...]]:
    """Build a DB-API procedure call with validated name and bound args."""

    safe_name = validate_identifier(procedure_name)
    safe_args = tuple(_validate_scalar(arg) for arg in args)
    placeholders = ", ".join("?" for _ in safe_args)
    return f"CALL {safe_name}({placeholders})", safe_args


__all__ = [
    "MAX_STORED_VALUE_LENGTH",
    "StoredSqlValueError",
    "build_safe_procedure_call",
    "create_schema",
    "fetch_orders_for_saved_report",
    "save_report_filter",
    "validate_identifier",
]
