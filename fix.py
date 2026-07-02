# Auto fix for zhangjiayang6835-cyber/ai-research#194
# 1782921258

import hmac


def secure_compare(a, b):
    """
    Constant-time comparison to prevent timing attacks.
    Uses hmac.compare_digest for secure string comparison.
    """
    if not isinstance(a, (str, bytes)):
        raise TypeError("Inputs must be str or bytes")
    if not isinstance(b, (str, bytes)):
        raise TypeError("Inputs must be str or bytes")
    
    # Convert str to bytes if necessary
    if isinstance(a, str):
        a = a.encode('utf-8')
    if isinstance(b, str):
        b = b.encode('utf-8')
    
    return hmac.compare_digest(a, b)


# Example vulnerable function that would be replaced
def vulnerable_compare(secret, user_input):
    """
    Vulnerable comparison - DO NOT USE
    This leaks timing information via early return on mismatch.
    """
    if len(secret) != len(user_input):
        return False
    for i in range(len(secret)):
        if secret[i] != user_input[i]:
            return False
    return True
print("fix #194")
