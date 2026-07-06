from flask import Flask, request, jsonify
import ldap
from ldap.filter import escape_filter_chars
from ldap.dn import escape_dn_chars

app = Flask(__name__)
LDAP_SERVER = "ldap://ldap.company.com"

@app.route("/api/ldap-login", methods=["POST"])
def ldap_login():
    try:
        username = request.json["username"]
        password = request.json["password"]

        # Escape LDAP special characters to prevent injection
        safe_username_dn = escape_dn_chars(username)
        safe_username_filter = escape_filter_chars(username)

        conn = ldap.initialize(LDAP_SERVER)
        conn.simple_bind_s(
            f"cn={safe_username_dn},ou=users,dc=company,dc=com",
            password
        )

        result = conn.search_s(
            "dc=company,dc=com",
            ldap.SCOPE_SUBTREE,
            f"(uid={safe_username_filter})"
        )
        return jsonify({"user": str(result)})
    except Exception as e:
        return jsonify({"error": str(e)}), 500
