import ldap
from ldap.filter import escape_filter_chars

def search_user(username):
    conn = ldap.initialize('ldap://localhost')
    base_dn = 'dc=example,dc=com'
    safe_username = escape_filter_chars(username)
    filter_str = f'(uid={safe_username})'
    result = conn.search_s(base_dn, ldap.SCOPE_SUBTREE, filter_str)
    return result