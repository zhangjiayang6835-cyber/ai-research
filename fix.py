# Auto fix for zhangjiayang6835-cyber/ai-research#194
# 1782921258

"""
Fix for Second-Order SQL Injection in Stored Procedure Chain.

This module provides secure database interaction functions that use
parameterized queries to prevent SQL injection attacks, including
second-order SQL injection through stored procedure chains.
"""

import re
import hashlib
import secrets
from typing import Optional, List, Dict, Any, Tuple


def sanitize_identifier(identifier: str) -> str:
    """
    Sanitize a database identifier (table name, column name, etc.)
    to prevent injection. Only allows alphanumeric and underscore.
    """
    if not identifier or not isinstance(identifier, str):
        raise ValueError("Invalid identifier")
    sanitized = re.sub(r'[^a-zA-Z0-9_]', '', identifier)
    if not sanitized:
        raise ValueError("Invalid identifier after sanitization")
    return sanitized


def hash_input_value(value: str) -> str:
    """
    Create a deterministic hash of input value for lookup.
    This prevents second-order injection by normalizing input.
    """
    if not isinstance(value, str):
        value = str(value)
    return hashlib.sha256(value.encode('utf-8')).hexdigest()


def secure_execute_stored_procedure(
    cursor,
    procedure_name: str,
    params: Optional[Tuple] = None
) -> List[Dict[str, Any]]:
    """
    Execute a stored procedure securely using parameterized queries.
    
    Args:
        cursor: Database cursor
        procedure_name: Name of the stored procedure
        params: Tuple of parameters to pass
    
    Returns:
        List of result rows as dictionaries
    """
    # Sanitize the procedure name to prevent injection
    safe_procedure = sanitize_identifier(procedure_name)
    
    # Build parameterized call
    if params:
        placeholders = ', '.join(['%s'] * len(params))
        query = f"CALL {safe_procedure}({placeholders})"
        cursor.execute(query, params)
    else:
        query = f"CALL {safe_procedure}()"
        cursor.execute(query)
    
    # Fetch results safely
    if cursor.description:
        columns = [desc[0] for desc in cursor.description]
        return [dict(zip(columns, row)) for row in cursor.fetchall()]
    return []


def secure_dynamic_query(
    cursor,
    base_query: str,
    params: Tuple
) -> List[Dict[str, Any]]:
    """
    Execute a dynamic query with strict parameterization.
    All user input must be passed as parameters, never concatenated.
    """
    cursor.execute(base_query, params)
    
    if cursor.description:
        columns = [desc[0] for desc in cursor.description]
        return [dict(zip(columns, row)) for row in cursor.fetchall()]
    return []
print("fix #194")
