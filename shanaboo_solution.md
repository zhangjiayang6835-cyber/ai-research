Based on the issue description, I need to fix an LDAP injection vulnerability. The issue mentions LDAP query concatenation with user input. Let me look at the relevant files in the repository to find where this LDAP code exists.

From the root listing, I can see several fix files and directories. Let me check the most likely locations for LDAP-related code.

The issue describes:
- LDAP query: `(&(uid={input})(userPassword={pwd}))`
- Attack: `*)(uid=*))` bypasses password check
- Fix needed: LDAP escaping library + parameterized queries, RFC 4514 escaping, escape `\* ( ) \0`, no empty binds

Let me check the existing fix files and the src directory for LDAP-related code.</think>```diff
--- /dev/null
+++ b/fix-ldap-injection-bypass.py
@@ -0,0 +1,118 @@
+#!/usr/bin/env python3
+"""
+Fix: LDAP Injection → Anonymous Bind Bypass
+
+Vulnerability: LDAP queries directly concatenate user input:
+    (&(uid={input})(userPassword={pwd}))
+Attacker input: *)(uid=*)) makes query:
+    (&(uid=*)(uid=*))(userPassword=...) → bypasses password check.
+
+Fix: RFC 4514/4515 compliant LDAP escaping + parameterized filter construction.
+"""
+
+import re
+import ldap3
+from ldap3 import Server, Connection, ALL, SAFE_SYNC
+from ldap3.utils.conv import escape_filter_chars
+
+
+# ---------------------------------------------------------------------------
+# RFC 4515 / RFC 4514 LDAP filter escaping
+# ---------------------------------------------------------------------------
+# Characters that MUST be escaped in LDAP search filters per RFC 4515:
+#   *  (  )  \  NUL (0x00)
+# Additionally, for DN values (RFC 4514), these also need escaping:
+#   +  ,  ;  <  >  "  #  =
+# We provide both functions for completeness.
+# ---------------------------------------------------------------------------
+
+# Characters requiring escape in LDAP filter values (RFC 4515 Section 3)
_LDAP_FILTER_ESCAPE_CHARS = {
    ord('*'):  r'\2a',
    ord('('):  r'\28',
    ord(')'):  r'\29',
    ord('\\'): r'\5c',
    ord('\0'): r'\00',
}
_LDAP_FILTER_ESCAPE_RE = re.compile(
    '[' + re.escape(''.join(chr(c) for c in _LDAP_FILTER_ESCAPE_CHARS)) + ']'
)


def escape_ldap_filter_value(value: str) -> str:
    """
    Escape a string for safe use as a value in an LDAP search filter.
    Complies with RFC 4515 Section 3.

    Escapes: * ( ) \\ NUL (0x00)

    Args:
        value: Raw user-provided string.

    Returns:
        Escaped string safe for LDAP filter value insertion.

    Raises:
        ValueError: If value is empty (prevents anonymous bind bypass).
    """
    if not value or not value.strip():
        raise ValueError("LDAP filter value must not be empty (anonymous bind prevention)")

    def _escape_char(match: re.Match) -> str:
        char = match.group(0)
        return _LDAP_FILTER_ESCAPE_CHARS.get(ord(char), char)

    return _LDAP_FILTER_ESCAPE_RE.sub(_escape_char, value)


def escape_ldap_dn_value(value: str) -> str:
    """
    Escape a string for safe use as a value in an LDAP Distinguished Name.
    Complies with RFC 4514.

    Escapes all RFC 4515 chars plus: + , ; < > " # = and leading/trailing spaces.

    Args:
        value: Raw user-provided string.

    Returns:
        Escaped string safe for DN value insertion.
    """
    if not value:
        raise ValueError("LDAP DN value must not be empty")

    # RFC 4514 special chars (in addition to RFC 4515 filter chars)
    dn_special = r'[+\",;<>#]'
    # Leading/trailing space and # at start
    escaped = value

    # Escape backslash first (must be first to avoid double-escaping)
    escaped = escaped.replace('\\', '\\5c')
    # Escape other DN special chars
    escaped = escaped.replace('+', '\\2b')
    escaped = escaped.replace(',', '\\2c')
    escaped = escaped.replace(';', '\\3b')
    escaped = escaped.replace('<', '\\3c')
    escaped = escaped.replace('>', '\\3e')
    escaped = escaped.replace('"', '\\22')
    escaped = escaped.replace('#', '\\23')
    escaped = escaped.replace('=', '\\3d')
    # Escape filter specials
    escaped = escaped.replace('*', '\\2a')
    escaped = escaped.replace('(', '\\28')
    escaped = escaped.replace(')', '\\29')
    escaped = escaped.replace('\0', '\\00')

    # Leading space
    if escaped.startswith(' '):
        escaped = '\\20' + escaped[1:]
    # Trailing space
    if escaped.endswith(' '):
        escaped = escaped[:-1] + '\\20'
    # Leading #
    if value.startswith('#'):
        escaped = '\\23' + escaped[1:]

    return escaped


# ---------------------------------------------------------------------------
# Safe LDAP authentication using parameterized filter construction
# ---------------------------------------------------------------------------

def ldap_authenticate(
    server_uri: str,
    base_dn: str,
    uid_attribute: str,
    username: str,
    password: str,
    use_ssl: bool = True,
) -> bool:
    """
    Authenticate a user against LDAP safely.

    Uses ldap3's built-in escape_filter_chars for filter construction
    AND explicit validation to prevent anonymous bind bypass.

    Args:
        server_uri: LDAP server URI (e.g., 'ldaps://ldap.example.com')
        base_dn: Base DN for search (e.g., 'dc=example,dc=com')
        uid_attribute: UID attribute name (e.g., 'uid')
        username: User-provided username
        password: User-provided password

    Returns:
        True if authentication succeeded, False otherwise.

    Raises:
        ValueError: If username or password is empty.
    """
    # --- Prevent empty binds (anonymous bind bypass) ---
    if not username or not username.strip():
        raise ValueError("Username must not be empty (anonymous bind prevention)")
    if not password or not password.strip():
        raise ValueError("Password must not be empty (anonymous bind prevention)")

   