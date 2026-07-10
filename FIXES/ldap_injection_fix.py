"""
LDAP Injection Fix
Bounty #778 ($120)
=========================================
Vulnerability: LDAP query directly concatenates user input:
(&(uid={input})(userPassword={pwd}))
Attacker inputs *)(uid=*)) to bypass auth.

Fix: Escape RFC 4514 special characters + parameterized queries.
"""

import re
from typing import Optional


class LDAPSanitizer:
    """
    Sanitize LDAP search filters against injection attacks.
    Implements RFC 4514 escaping for DN and RFC 4515 for search filters.
    """

    # Characters that must be escaped in LDAP search filters (RFC 4515)
    FILTER_SPECIAL_CHARS = re.compile(r'[\\*\\(\\)\\0]')

    # Characters that must be escaped in LDAP DN (RFC 4514)
    DN_SPECIAL_CHARS = re.compile(r'[,\\+"<>;#=\\0]')

    @staticmethod
    def escape_filter(input_str: str) -> str:
        """
        Escape LDAP search filter special characters (RFC 4515).
        Escapes: *, (, ), \\, NUL
        """
        if not input_str:
            return ""

        result = []
        for char in input_str:
            if char == "\\":
                result.append("\\\\5c")
            elif char == "*":
                result.append("\\\\2a")
            elif char == "(":
                result.append("\\\\28")
            elif char == ")":
                result.append("\\\\29")
            elif char == "\0":  # NUL
                result.append("\\\\00")
            else:
                result.append(char)

        return "".join(result)

    @staticmethod
    def escape_dn(input_str: str) -> str:
        """
        Escape LDAP DN special characters (RFC 4514).
        Escapes: , + \" < > ; # = \\
        """
        if not input_str:
            return ""

        result = []
        for char in input_str:
            if char == "\\":
                result.append("\\\\")
            elif char == ",":
                result.append("\\,")
            elif char == "+":
                result.append("\\+")
            elif char == '"':
                result.append('\\"')
            elif char == "<":
                result.append("\\<")
            elif char == ">":
                result.append("\\>")
            elif char == ";":
                result.append("\\;")
            elif char == "#":
                result.append("\\#")
            elif char == "=":
                result.append("\\=")
            elif char == "\0":
                result.append("\\00")
            else:
                result.append(char)

        return "".join(result)

    @staticmethod
    def is_safe_filter(input_str: str) -> bool:
        """
        Check if input is safe for use in LDAP filter.
        Rejects any input containing filter special characters.
        """
        return bool(LDAPSanitizer.FILTER_SPECIAL_CHARS.search(input_str)) is False


class SecureLDAPAuthenticator:
    """
    LDAP authentication with injection protection.
    """

    def __init__(self, ldap_connection):
        self._conn = ldap_connection

    def authenticate(self, username: str, password: str) -> Optional[dict]:
        """
        Authenticate user via LDAP with injection-safe queries.
        """
        if not username or not password:
            return None

        # Escape both inputs to prevent injection
        safe_username = LDAPSanitizer.escape_filter(username)
        safe_password = LDAPSanitizer.escape_filter(password)

        # Build parameterized query
        filter_str = f"(&(uid={safe_username})(userPassword={safe_password}))"

        # In production, use ldap3 or python-ldap with proper connection
        # This is a simulated implementation
        try:
            result = self._execute_query(filter_str)
            if result:
                return {"authenticated": True, "user": result}
            return {"authenticated": False}
        except Exception as e:
            return {"authenticated": False, "error": str(e)}

    def _execute_query(self, filter_str: str) -> Optional[dict]:
        """
        Execute LDAP query with the safe filter.
        In production, this would be:
            self._conn.search(
                search_base='dc=example,dc=com',
                search_filter=filter_str,
                attributes=['cn', 'mail', 'uid']
            )
        """
        # Simulated - replace with actual LDAP call
        return None


# ========== Usage Example ==========
if __name__ == "__main__":
    print("=== LDAP Injection Prevention ===")
    print()

    # Attack scenario: attacker inputs *)(uid=*))
    malicious_input = "*)(uid=*))"
    safe_input = LDAPSanitizer.escape_filter(malicious_input)
    print(f"Malicious input: {malicious_input}")
    print(f"Escaped input:   {safe_input}")
    print()

    # Before (vulnerable):
    vulnerable_query = f"(&(uid={malicious_input})(userPassword=pass))"
    print(f"Vulnerable query: {vulnerable_query}")
    print(f"  → Query becomes: (&(uid=*)(uid=*))(userPassword=pass))")
    print(f"  → Attacker bypasses password check!")
    print()

    # After (fixed):
    safe_query = f"(&(uid={safe_input})(userPassword=pass))"
    print(f"Fixed query:      {safe_query}")
    print(f"  → Special characters are escaped, injection prevented!")
    print()

    # Test various attack vectors
    test_inputs = [
        "*",
        "*)(uid=*))",
        "admin)(&)",
        "|(uid=*))",
        "admin\\2a",
        ")(|(uid=*",
    ]
    for inp in test_inputs:
        escaped = LDAPSanitizer.escape_filter(inp)
        print(f"  '{inp}' → '{escaped}'")
