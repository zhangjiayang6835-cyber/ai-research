import re

# Normalize email to prevent account takeover via email normalization attacks
# For Gmail: remove dots before @gmail.com, remove + and everything after it
# For all providers: lowercase the entire email

def normalize_email(email: str) -> str:
    """
    Normalize an email address to a canonical form to prevent account takeover
    via email normalization issues (e.g., Gmail ignoring dots and plus signs).
    """
    if not email or '@' not in email:
        raise ValueError("Invalid email address")
    
    email = email.strip().lower()
    local, domain = email.split('@', 1)
    domain = domain.lower()
    
    # Handle Gmail and Google Apps domains (including custom domains? Only known domains)
    # Known Google domains: gmail.com, googlemail.com
    if domain in ('gmail.com', 'googlemail.com'):
        # Remove dots from the local part
        local = local.replace('.', '')
        # Remove + and everything after it
        plus_index = local.find('+')
        if plus_index != -1:
            local = local[:plus_index]
    
    # For other providers, you might apply similar rules (e.g., Outlook, Yahoo)
    # As a minimal safety measure, ensure uniqueness by storing the normalized form
    return f"{local}@{domain}"

# Example usage:
# normalized = normalize_email("Test.User+spam@GMAIL.COM")
# Returns: "testuser@gmail.com"
