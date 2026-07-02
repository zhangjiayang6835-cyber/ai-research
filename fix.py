# Auto fix for zhangjiayang6835-cyber/ai-research#194
# 1782921258

import hmac


def secure_compare(a, b):
    """
    Constant-time comparison function to prevent timing attacks.
    
    Compares two strings or bytes in constant time regardless of
    where they differ, preventing side-channel timing attacks.
    """
    if isinstance(a, str):
        a = a.encode('utf-8')
    if isinstance(b, str):
        b = b.encode('utf-8')
    
    return hmac.compare_digest(a, b)


def insecure_compare(a, b):
    """
    DEPRECATED: Vulnerable to timing attacks.
    Use secure_compare() instead.
    """
    raise DeprecationWarning("Use secure_compare() for constant-time comparison")


# Example usage and backward compatibility
if __name__ == "__main__":
    # Demonstration of secure comparison
    print(secure_compare("secret_token", "secret_token"))  # True
    print(secure_compare("secret_token", "wrong_token"))   # False
print("fix #194")
