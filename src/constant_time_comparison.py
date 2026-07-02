"""
Constant-time comparison utilities to prevent timing attacks.
"""

import hmac


def secure_compare(a: bytes, b: bytes) -> bool:
    """
    Compare two byte strings in constant time to prevent timing attacks.
    
    This function uses hmac.compare_digest which is designed to take
    approximately the same amount of time regardless of how many bytes
    match between the two inputs.
    
    Args:
        a: First byte string to compare
        b: Second byte string to compare
    
    Returns:
        True if the byte strings are equal, False otherwise
    
    Raises:
        TypeError: If inputs are not bytes-like objects
    """
    return hmac.compare_digest(a, b)


def insecure_compare(a: bytes, b: bytes) -> bool:
    """
    INSECURE: Early-exit comparison vulnerable to timing attacks.
    DO NOT USE in security-sensitive contexts.
    
    This function returns immediately on first mismatch, which allows
    attackers to determine the correct bytes through timing analysis.
    """
    if len(a) != len(b):
        return False
    for x, y in zip(a, b):
        if x != y:
            return False
    return True


__all__ = ['secure_compare', 'insecure_compare']