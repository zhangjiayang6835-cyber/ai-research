# Auto fix for zhangjiayang6835-cyber/ai-research#194
# 1782921258

import hmac


def secure_compare(a, b):
    """
    Constant-time comparison function to prevent timing attacks.
    
    Compares two strings or bytes in constant time, regardless of
    how many characters match, to prevent timing side-channel attacks.
    
    Args:
        a: First string or bytes to compare
        b: Second string or bytes to compare
    
    Returns:
        bool: True if a and b are equal, False otherwise
    """
    # Convert to bytes if strings
    if isinstance(a, str):
        a = a.encode('utf-8')
    if isinstance(b, str):
        b = b.encode('utf-8')
    
    # Use hmac.compare_digest for constant-time comparison
    # This is the recommended approach in Python 3.3+
    try:
        return hmac.compare_digest(a, b)
    except TypeError:
        return False
print("fix #194")
