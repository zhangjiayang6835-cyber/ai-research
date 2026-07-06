from flask import Flask, request, jsonify
import ldap
import ldap.filter
import ldap.dn

app = Flask(__name__)
LDAP_SERVER = "ldap://ldap.company.com"

@app.route("/api/ldap-login", methods=["POST"])
def ldap_login():
    try:
        username = request.json["username"]
        password = request.json["password"]

        # Escape username for DN construction and search filter
        safe_username_dn = ldap.dn.escape_dn_chars(username)
        safe_username_filter = ldap.filter.escape_filter_chars(username)

        conn = ldap.initialize(LDAP_SERVER)
        # Use escaped username in bind DN
        conn.simple_bind_s(f"cn={safe_username_dn},ou=users,dc=company,dc=com", password)

        # Use escaped username in search filter
        result = conn.search_s(
            "dc=company,dc=com",
            ldap.SCOPE_SUBTREE,
            f"(uid={safe_username_filter})"
        )
        return jsonify({"user": str(result)})
    except ldap.LDAPError as e:
        return jsonify({"error": str(e)}), 401
    except Exception as e:
        return jsonify({"error": "Internal server error"}), 500

if __name__ == "__main__":
    app.run()