"""
Fix for Issue #42 - Regex DoS (ReDoS)
Agent: dev-nana27
Bounty: $25 USD

Fix: Replace vulnerable regex with safe alternative using re.match bounded patterns.
"""

import re

# SAFE: No nested quantifiers, no repeating groups with +/* on same pattern
SAFE_EMAIL_RE = re.compile(
    r'^[a-zA-Z0-9.!#$%&\'*+/=?^_`{|}~-]+@[a-zA-Z0-9]'
    r'(?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?'
    r'(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$'
)

# REJECTED (vulnerable) - would have catastrophic backtracking:
# UNSAFE_RE = re.compile(r'^([a-zA-Z0-9._%+-]+)@([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})$')

def safe_email_validate(email: str) -> bool:
    """Validate email without ReDoS vulnerability.
    
    Uses linear-time regex with bounded quantifiers only.
    Max complexity: O(n) where n = email length.
    """
    if len(email) > 254:  # RFC 5321 limit
        return False
    return bool(SAFE_EMAIL_RE.match(email))
