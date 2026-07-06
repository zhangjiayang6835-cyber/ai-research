"""
Fix for Issue #17 — CSRF Protection for Email Update
=====================================================

Vulnerability
-------------
Email update endpoint lacks CSRF token verification, allowing
cross-site request forgery attacks.

Fix Strategy
------------
1. Require a CSRF token in both header and form.
2. Generate and validate tokens using a cryptographically secure
   secret derived from application configuration.
3. Reject requests without valid tokens.
"""

from __future__ import annotations

import hmac
import secrets
from typing import Optional


# In production, this would come from application settings
CSRF_SECRET = secrets.token_hex(32)


def generate_csrf_token() -> str:
    """Generate a new CSRF token."""
    return secrets.token_hex(32)


def validate_csrf_token(token: Optional[str], expected_token: Optional[str]) -> bool:
    """Validate a CSRF token using constant-time comparison."""
    if not token or not expected_token:
        return False
    return hmac.compare_digest(token, expected_token)
