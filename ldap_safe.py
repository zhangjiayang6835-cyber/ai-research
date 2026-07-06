import ldap3
from ldap3.utils.conv import escape_filter_chars

def safe_ldap_search(server_uri, base_dn, search_filter_attribute, search_value, attributes=None):
    """
    Perform an LDAP search with proper escaping to prevent injection.

    :param server_uri: LDAP server URI (e.g., 'ldap://localhost:389')
    :param base_dn: Base DN for the search
    :param search_filter_attribute: Attribute to search (e.g., 'uid')
    :param search_value: User-provided search value (will be escaped)
    :param attributes: List of attributes to retrieve (default: all)
    :return: List of entries
    """
    # Escape user input to prevent LDAP injection
    escaped_value = escape_filter_chars(search_value)
    # Build filter safely using escaped value
    search_filter = f"({search_filter_attribute}={escaped_value})"

    server = ldap3.Server(server_uri)
    conn = ldap3.Connection(server, auto_bind=True)
    conn.search(
        search_base=base_dn,
        search_filter=search_filter,
        search_scope=ldap3.SUBTREE,
        attributes=attributes if attributes else ldap3.ALL_ATTRIBUTES
    )
    return conn.entries
