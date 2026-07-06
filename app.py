from flask import Flask, request, jsonify
import ldap
from ldap.filter import escape_filter_chars

app = Flask(__name__)
LDAP_SERVER = "ldap://ldap.company.com"

def escape_ldap_dn(value):
    """Escape special characters for LDAP DN components."""
    # Characters to escape: , = + < > # ; \ " ( ) and space at beginning/end
    escape_chars = {
        ',': '\\2C',
        '=': '\\3D',
        '+': '\\2B',
        '<': '\\3C',
        '>': '\\3E',
        '#': '\\23',
        ';': '\\3B',
        '\\': '\\5C',
        '"': '\\22',
        '(': '\\28',
        ')': '\\29',
        ' ': '\\20',
    }
    result = []
    for ch in value:
        if ch in escape_chars:
            result.append(escape_chars[ch])
        else:
            result.append(ch)
    return ''.join(result)

@app.route("/api/ldap-login", methods=["POST"])
def ldap_login():
    username = request.json["username"]
    password = request.json["password"]
    
    conn = ldap.initialize(LDAP_SERVER)
    # Escape the username for DN (though DN escaping is less critical than filter, but good practice)
    safe_username_dn = escape_ldap_dn(username)
    conn.simple_bind_s(f"cn={safe_username_dn},ou=users,dc=company,dc=com", password)
    
    # Escape username for LDAP filter to prevent injection
    safe_username_filter = escape_filter_chars(username)
    result = conn.search_s(
        "dc=company,dc=com",
        ldap.SCOPE_SUBTREE,
        f"(uid={safe_username_filter})"
    )
    return jsonify({"user": str(result)})
