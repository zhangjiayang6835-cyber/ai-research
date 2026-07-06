from ldap3.utils.conv import escape_filter_chars

def safe_ldap_query(base_dn, search_filter_template, parameters):
    """
    Safely construct an LDAP query by escaping user-supplied parameters.

    :param base_dn: Base distinguished name (e.g., 'dc=example,dc=com')
    :param search_filter_template: LDAP filter template with placeholders (e.g., '(uid={0})')
    :param parameters: List of parameter values to be substituted into the template
    :return: Tuple (base_dn, search_filter) safe for use with ldap3
    """
    escaped_params = [escape_filter_chars(str(param)) for param in parameters]
    search_filter = search_filter_template.format(*escaped_params)
    return base_dn, search_filter

# Example usage:
# from ldap3 import Server, Connection, ALL
# server = Server('ldap://localhost', get_info=ALL)
# conn = Connection(server, user='cn=admin,dc=example,dc=com', password='secret')
# base_dn, safe_filter = safe_ldap_query('dc=example,dc=com', '(uid={0})', ['admin'])
# conn.search(base_dn, safe_filter, attributes=['cn', 'mail'])
# print(conn.entries)
