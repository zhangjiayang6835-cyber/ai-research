"""
Authentication utilities with secure email normalization.
Prevents account takeover via email normalization attacks.
"""

import re


def normalize_email(email: str) -> str:
    """
    Normalize email address securely to prevent account takeover.
    
    Rules:
    - Strip leading/trailing whitespace
    - Convert to lowercase
    - Reject emails with '+' in local part (prevents alias-based ATO)
    - Reject IDN homograph attacks by checking for suspicious unicode
    - Validate basic email structure
    
    Returns normalized email or raises ValueError for invalid emails.
    """
    if not email or not isinstance(email, str):
        raise ValueError("Email must be a non-empty string")
    
    # Strip whitespace
    email = email.strip()
    
    # Basic structure validation
    if "@" not in email or email.count("@") != 1:
        raise ValueError("Invalid email format")
    
    local, domain = email.rsplit("@", 1)
    
    # Reject empty parts
    if not local or not domain:
        raise ValueError("Invalid email format")
    
    # Reject plus-addressing (common ATO vector via normalization differences)
    if "+" in local:
        raise ValueError("Plus-addressed emails are not allowed")
    
    # Convert to lowercase
    email = email.lower()
    
    # Reject IDN homograph attacks (mixed scripts)
    if re.search(r'[\u0080-\uffff]', email):
        raise ValueError("Non-ASCII characters in email are not allowed")
    
    return email