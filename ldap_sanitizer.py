import re


def sanitize_ldap_filter(user_input: str) -> str:
    """
    Sanitize user input to prevent LDAP injection in filter strings.
    Escapes special characters according to RFC 4515 and additional
    logic operators to prevent blind Boolean-based extraction.

    Args:
        user_input: The raw user input string.

    Returns:
        Escaped string safe for use in LDAP filter.
    """
    # Mapping of dangerous characters to their RFC 4515 hex escapes
    dangerous_chars = {
        '\\': '\\5c',
        '*': '\\2a',
        '(': '\\28',
        ')': '\\29',
        '\0': '\\00',
        '&': '\\26',
        '|': '\\7c',
        '!': '\\21',
        '=': '\\3d',
        '~': '\\7e',
        '<': '\\3c',
        '>': '\\3e',
    }
    result = []
    for ch in user_input:
        if ch in dangerous_chars:
            result.append(dangerous_chars[ch])
        else:
            result.append(ch)
    return ''.join(result)


# Example usage
def authenticate_user(username: str, password: str) -> bool:
    """
    Example function that uses sanitized LDAP filter.
    """
    safe_username = sanitize_ldap_filter(username)
    safe_password = sanitize_ldap_filter(password)
    ldap_filter = f"(&(uid={safe_username})(userPassword={safe_password}))"
    # Proceed with LDAP search using ldap_filter
    # ...
    return True  # Placeholder
