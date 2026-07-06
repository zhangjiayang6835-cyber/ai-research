"""
Fix for Issue #20 — NoSQL Injection in Login
=============================================

Vulnerability
-------------
MongoDB login query passes user input directly into the query
dictionary, allowing attackers to inject operators like ``$gt``,
``$ne`` to bypass authentication.

Fix Strategy
------------
1. Never pass user input directly as query operators.
2. Use exact-match queries only for authentication.
3. Validate input types (must be strings/numbers).
"""

from __future__ import annotations

from typing import Any, Dict, Optional


def safe_login_query(username: str, password: str) -> Dict[str, Any]:
    """
    Build a safe MongoDB login query.
    
    Args:
        username: User-supplied username.
        password: User-supplied password.
    
    Returns:
        Safe query dict for MongoDB authentication.
    """
    # Validate input types
    if not isinstance(username, str) or not isinstance(password, str):
        return {}
    
    # Reject suspicious characters that might indicate injection
    if "$" in username or "$" in password:
        return {}
    
    # Exact match only - no operators
    return {
        "username": username,
        "password": password
    }
