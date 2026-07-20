"""SQL Injection Fix — Issue #1428 (bounty)

Fixes vulnerable query_users() function that concatenates user input
directly into SQL strings instead of using parameterized queries.

Vulnerable pattern:
    "SELECT * FROM users WHERE username = '" + username + "'"

Safe pattern:
    cursor.execute("SELECT * FROM users WHERE username = ?", (username,))

Acceptance criteria:
- [x] Uses parameterized queries with ? placeholders
- [x] No string concatenation in SQL
- [x] Returns list of dicts for easy serialization
- [x] Handles empty/missing username gracefully
"""

import sqlite3
from typing import List, Dict


def query_users(conn: sqlite3.Connection, params: dict) -> list:
    """Query the users table by username using parameterized queries.

    Args:
        conn: Active SQLite connection.
        params: Dictionary containing at least a 'username' key.

    Returns:
        List of matching user rows as dicts.

    Raises:
        ValueError: If username is missing or empty.
        sqlite3.Error: On database errors.
    """
    username = params.get("username", "").strip()
    if not username:
        raise ValueError("username is required")

    query = "SELECT id, username, email FROM users WHERE username = ?"
    cursor = conn.execute(query, (username,))
    rows = cursor.fetchall()

    return [
        {"id": row[0], "username": row[1], "email": row[2]}
        for row in rows
    ]


if __name__ == "__main__":
    # Quick self-test
    conn = sqlite3.connect(":memory:")
    conn.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, email TEXT)")
    conn.execute("INSERT INTO users VALUES (1, 'alice', 'alice@example.com')")
    conn.execute("INSERT INTO users VALUES (2, 'bob', 'bob@example.com')")

    result = query_users(conn, {"username": "alice"})
    assert len(result) == 1
    assert result[0]["id"] == 1
    assert result[0]["email"] == "alice@example.com"

    # Test injection attempt is neutralized
    result = query_users(conn, {"username": "' OR 1=1 --"})
    assert len(result) == 0

    # Test empty username
    try:
        query_users(conn, {"username": ""})
        assert False, "Should have raised ValueError"
    except ValueError:
        pass

    print("✅ All tests passed")
