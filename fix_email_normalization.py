import re

def normalize_email(email: str) -> str:
    '''
    Normalize an email address to prevent zero-click account takeover.
    Handles case insensitivity, Gmail dot and plus addressing.
    Extend as needed for other providers (e.g., Outlook, Yahoo).

    Args:
        email: Raw email input.

    Returns:
        Normalized email string.

    Raises:
        ValueError: If email is invalid (optional).
    '''
    if not email or '@' not in email:
        raise ValueError('Invalid email address')
    email = email.strip().lower()
    local_part, domain = email.rsplit('@', 1)
    # Gmail/Googlemail normalization
    if domain in ('gmail.com', 'googlemail.com'):
        # Remove all dots from local part
        local_part = local_part.replace('.', '')
        # Remove everything after '+'
        local_part = local_part.split('+')[0]
    # Add other domain-specific rules (e.g., Microsoft, Yahoo) as needed.
    return f'{local_part}@{domain}'

def is_email_taken(email: str, existing_emails: set) -> bool:
    '''
    Check if a normalized email already exists in the set.

    Args:
        email: Raw email to check.
        existing_emails: Set of normalized existing emails.

    Returns:
        True if taken, False otherwise.
    '''
    normalized = normalize_email(email)
    return normalized in existing_emails
