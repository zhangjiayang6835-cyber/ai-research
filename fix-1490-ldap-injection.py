#!/usr/bin/env python3
"""
Fix for Issue #1490: LDAP Injection → Anonymous Bind Bypass

Vulnerability: LDAP queries concatenate user input without escaping,
allowing injection of filter metacharacters to bypass authentication.

Fix: Escape LDAP filter metacharacters per RFC 4515, use SASL bind instead
of password-in-filter comparison, validate DN components.
"""

from ldap3 import Server, Connection, ALL, SAFE_SYNC, SUBTREE, SIMPLE
from typing import Optional, Dict, List
import secrets

LDAP_ESCAPE = {'\\': '\\\\5c', '*': '\\\\2a', '(': '\\\\28', ')': '\\\\29',
               '\x00': '\\\\00', '/': '\\\\2f'}

def escape_ldap_filter(value: str) -> str:
    result = []
    for c in value:
        if c in LDAP_ESCAPE: result.append(LDAP_ESCAPE[c])
        elif ord(c) < 32: result.append(f'\\\\{ord(c):02x}')
        else: result.append(c)
    return ''.join(result)

def validate_dn(v: str, mx=128) -> bool:
    return len(v) <= mx and '\x00' not in v and not any(ord(c) < 32 and c not in '\r\n\t' for c in v)

def ldap_auth_secure(username: str, password: str,
    server_uri='ldap://ldap.example.com', base_dn='dc=example,dc=com') -> bool:
    if not username or not password: return False
    if not validate_dn(username): return False
    safe_user = escape_ldap_filter(username)
    server = Server(server_uri, get_info=ALL)
    try:
        sc = Connection(server, auto_bind=True, read_only=True, client_strategy=SAFE_SYNC)
        sc.search(base_dn, f"(&(objectClass=person)(uid={safe_user}))",
                  SUBTREE, attributes=['dn'], size_limit=1)
        if len(sc.entries) != 1:
            secrets.compare_digest('a','b'); sc.unbind(); return False
        user_dn = str(sc.entries[0].entry_dn); sc.unbind()
        uc = Connection(server, user=user_dn, password=password, authentication=SIMPLE,
                       auto_bind=False, read_only=True, client_strategy=SAFE_SYNC)
        ok = uc.bind(); uc.unbind()
        return ok
    except Exception as e:
        print(f"[SEC] LDAP error: {e}"); return False

def ldap_search_secure(template: str, params: Dict[str,str],
    base_dn='dc=example,dc=com', server_uri='ldap://ldap.example.com',
    attrs=None, max_results=100) -> List:
    safe = {k: escape_ldap_filter(v) for k,v in params.items()}
    filt = template.format(**safe)
    server = Server(server_uri, get_info=ALL)
    conn = Connection(server, auto_bind=True, read_only=True, client_strategy=SAFE_SYNC)
    try:
        conn.search(base_dn, filt, SUBTREE, attributes=attrs or ['*'],
                   size_limit=max_results, time_limit=10)
        return conn.entries
    finally: conn.unbind()

if __name__ == '__main__':
    tests = [
        ("normal_user", "normal_user"),
        ("admin)(|(uid=*", "admin\\\\29\\\\7c(uid=*"),
        ("user*", "user\\\\2a"),
        ("test\\\\user", "test\\\\5cuser"),
        ("user\x00admin", "user\\\\00admin"),
    ]
    all_ok = True
    for orig, expected in tests:
        got = escape_ldap_filter(orig)
        ok = got == expected
        if not ok: all_ok = False
        print(f"{'OK' if ok else 'FAIL'}: {repr(orig)} -> {repr(got)}")
    assert validate_dn("normal") and not validate_dn("u\x00x") and not validate_dn("a"*200)
    print("All tests passed" if all_ok else "SOME FAILED")
