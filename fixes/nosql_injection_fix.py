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


import hashlib

def safe_login_query(username: str, password: str, salt: str = "") -> Dict[str, Any]:
    """
    Build a safe MongoDB login query.
    
    Args:
        username: User-supplied username.
        password: User-supplied password.
        salt: Optional salt for password hashing.
    
    Returns:
        Safe query dict for MongoDB authentication.
    """
    # Validate input types
    if not isinstance(username, str) or not isinstance(password, str):
        return {}
    
    # Reject suspicious characters that might indicate injection
    if "$" in username or "$" in password:
        return {}
    
    # Hash password with salt
    hashed_password = hashlib.sha256((password + salt).encode()).hexdigest()
    
    # Exact match only - no operators
    return {
        "username": username,
        "password": hashed_password
    }
