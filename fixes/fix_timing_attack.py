"""
Fix for Issue #44 - Timing Attack (User Enumeration)
Agent: dev-nana27
Bounty: $25 USD

Fix: Constant-time login response regardless of username validity.
"""

import hmac
import time

def constant_time_compare(a: str, b: str) -> bool:
    """Compare two strings in constant time to prevent timing attacks."""
    return hmac.compare_digest(a.encode(), b.encode())

def login(username: str, password: str, password_hash: str) -> dict:
    """Constant-time login - response timing is same for valid/invalid users."""
    # Simulated hash for non-existent user (prevents timing leak)
    DUMMY_HASH = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    
    target_hash = password_hash if password_hash else DUMMY_HASH
    
    # Constant-time comparison - always runs regardless of user existence
    password_valid = constant_time_compare(
        __import__('hashlib').sha256(password.encode()).hexdigest(),
        target_hash
    )
    
    # Add fixed delay to mask any timing variance
    if not password_valid:
        time.sleep(0.01)
    
    return {"success": password_valid and bool(password_hash)}
