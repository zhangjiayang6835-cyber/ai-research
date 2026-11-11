import ldap3

def safe_ldap_search(base_dn, filter_str, user_input):
    """
    Performs a secure LDAP search by escaping user input.
    """
    escaped_input = ldap3.utils.conv.escape_filter_chars(user_input)
    safe_filter = f"(&(uid={escaped_input})(objectClass=person))"
    return safe_filter
