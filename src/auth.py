"""
Authentication module with secure email normalization.
Fixes Zero-Click Account Takeover via Email Normalization vulnerability.
"""

import re
import unicodedata
from typing import Optional
import hashlib
import hmac


def _validate_email_format(email: str) -> bool:
    """
    Validate that the email has a proper format.
    """
    if not email or not isinstance(email, str):
        return False
    
    # Basic email format validation
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None


def normalize_email(email: str) -> str:
    """
    Securely normalize an email address to prevent account takeover.
    
    Security measures:
    1. Strip whitespace and control characters
    2. Normalize to NFC unicode form
    3. Convert to lowercase
    4. Validate against homograph attacks (mixed scripts)
    5. Prevent case-based and normalization-based collisions
    
    Args:
        email: The raw email input
        
    Returns:
        Normalized email string
        
    Raises:
        ValueError: If email is invalid or contains suspicious patterns
    """
    if not email or not isinstance(email, str):
        raise ValueError("Email must be a non-empty string")
    
    # Step 1: Strip whitespace and control characters
    email = email.strip()
    
    # Reject emails with dangerous control characters
    if any(ord(c) < 32 for c in email):
        raise ValueError("Email contains invalid control characters")
    
    # Step 2: Normalize unicode to prevent normalization-based collisions
    # NFC form prevents different unicode sequences from matching the same visual string
    email = unicodedata.normalize('NFC', email)
    
    # Step 3: Split local part and domain
    if '@' not in email:
        raise ValueError("Invalid email format: missing @ symbol")
    
    parts = email.rsplit('@', 1)
    local_part = parts[0]
    domain = parts[1]
    
    if not local_part or not domain:
        raise ValueError("Invalid email format")
    
    # Step 4: Normalize domain to lowercase
    domain = domain.lower()
    
    # Step 5: Handle local part normalization based on provider rules
    # Gmail: dots are ignored, plus aliases are stripped
    # This must be done consistently to prevent collisions
    if domain in ('gmail.com', 'googlemail.com'):
        # Remove dots from local part (Gmail ignores dots)
        local_part = local_part.replace('.', '')
        # Strip plus aliases (everything after +)
        if '+' in local_part:
            local_part = local_part.split('+')[0]
    
    # Step 6: Convert to lowercase for case-insensitive comparison
    # Note: Some email providers are case-sensitive for local part,
    # but for security and consistency we lowercase to prevent collisions
    local_part = local_part.lower()
    
    # Step 7: Reconstruct normalized email
    normalized = f"{local_part}@{domain}"
    
    # Step 8: Final validation
    if not _validate_email_format(normalized):
        raise ValueError("Email format is invalid after normalization")
    
    # Step 9: Check for homograph attacks (mixed scripts)
    # This prevents visually similar characters from different scripts
    # being used to create lookalike emails
    for char in local_part:
        if unicodedata.category(char).startswith('Lo'):  # Other_Letter
            # Check for specific script
            script = unicodedata.name(char, 'UNKNOWN').split()[0]
            if script in ('CYRILLIC', 'GREEK', 'ARMENIAN', 'GEORGIAN'):
                raise ValueError("Potentially deceptive mixed-script email detected")
    
    return normalized


def emails_equal(email1: str, email2: str) -> bool:
    """
    Compare two emails for equality using secure normalization.
    
    Args:
        email1: First email to compare
        email2: Second email to compare
        
    Returns:
        True if emails are equivalent, False otherwise
    """
    try:
        return normalize_email(email1) == normalize_email(email2)
    except ValueError:
        return False


def get_email_hash(email: str, secret_key: Optional[str] = None) -> str:
    """
    Get a secure hash of the normalized email for storage/comparison.
    
    Args:
        email: The email to hash
        secret_key: Optional secret key for HMAC
        
    Returns:
        Hex digest of the hashed email
    """
    normalized = normalize_email(email)
    
    if secret_key:
        return hmac.new(
            secret_key.encode() if isinstance(secret_key, str) else secret_key,
            normalized.encode(),
            hashlib.sha256
        ).hexdigest()
    
    return hashlib.sha256(normalized.encode()).hexdigest()