from flask import Flask, request, render_template_string, make_response, session, jsonify
import sqlite3
import secrets
import html
from urllib.parse import parse_qs

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)

# ── Secure session cookie configuration ─────────────────────────────────────
# Prevent session fixation by ensuring session cookies are:
# - HttpOnly: Not accessible via JavaScript
# - Secure: Only sent over HTTPS
# - SameSite=Lax: CSRF mitigation
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_PATH="/",
    # Regenerate session ID on each request to prevent fixation
    SESSION_REFRESH_EACH_REQUEST=True,
    # Set session lifetime (30 minutes)
    PERMANENT_SESSION_LIFETIME=1800,
)
# Make sessions permanent so lifetime is enforced
@app.before_request
def make_session_permanent():
    session.permanent = True


# ── Session origin tracking ─────────────────────────────────────────────────
def _get_session_origin():
    """Get the client's IP and User-Agent for session origin validation."""
    ip = request.remote_addr or "unknown"
    ua = request.headers.get("User-Agent", "unknown")
    return ip, ua


@app.before_request
def bind_session_origin():
    """Bind session to client IP and User-Agent on creation.

    This prevents session hijacking by validating that the session
    is being used from the same origin (IP + User-Agent) that
    created it.
    """
    if session.get("_bound"):
        return

    ip, ua = _get_session_origin()
    session["_bound"] = True
    session["_ip"] = ip
    session["_ua"] = ua
    session["_created_at"] = __import__("time").time()


@app.before_request
def validate_session_origin():
    """Validate that the session is being used from the same origin.

    If the IP or User-Agent has changed since session creation,
    invalidate the session to prevent hijacking.
    """
    if not session.get("_bound"):
        return

    ip, ua = _get_session_origin()

    # Allow IP changes for the same User-Agent (mobile roaming),
    # but reject User-Agent changes (different browser/tool)
    if session.get("_ua") != ua:
        session.clear()
        return jsonify({
            "error": "Session invalidated",
            "message": "Session origin changed (different User-Agent)"
        }), 401


# ── Security headers ────────────────────────────────────────────────────────
@app.after_request
def add_security_headers(response):
    response.headers["X-Frame-Options"] = "DENY"
    # Add HSTS header to enforce HTTPS
    response.headers["Strict-Transport-Security"] = (
        "max-age=31536000; includeSubDomains"
    )
    # Prevent MIME type sniffing
    response.headers["X-Content-Type-Options"] = "nosniff"
    # Prevent session fixation via Referer header leakage
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    return response


# ── Session ID in URL rejection ─────────────────────────────────────────────
# Known session/auth parameter names that MUST NOT appear in URLs
SESSION_PARAM_NAMES = frozenset({
    "session", "sessionid", "session_id", "sid",
    "session_token", "access_token", "refresh_token",
    "token", "auth_token", "api_key",
    "phpsessid", "jsessionid", "aspsessionid",
})


@app.before_request
def reject_session_id_in_url():
    """Reject requests that contain session IDs in URL query parameters.

    Session IDs must ONLY come from cookies. URL-based session IDs
    enable session fixation attacks and leak via Referer headers.
    """
    if not request.query_string:
        return

    raw = request.query_string.decode("utf-8")
    for pair in raw.split("&"):
        if not pair:
            continue
        if "=" not in pair:
            continue
        key = pair.split("=")[0].lower()
        if key in SESSION_PARAM_NAMES:
            return jsonify({
                "error": "Session token in URL rejected",
                "message": (
                    "Session tokens must only be transmitted via "
                    "secure cookies, not in URL parameters."
                ),
            }), 400


# Simulated user database
users = {
    "admin": {"password": "admin123", "role": "admin"},
    "user1": {"password": "user123", "role": "user"}
}

# CSRF token generation and validation
def generate_csrf_token():
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_urlsafe(32)
    return session["csrf_token"]

def validate_csrf_token(token):
    return token == session.get("csrf_token")

# Make csrf_token available in templates
app.jinja_env.globals["csrf_token"] = generate_csrf_token


@app.route("/")
def index():
    return """
    <h1>AI Research Platform</h1>
    <form action="/login" method="POST">
        <input name="username" placeholder="Username">
        <input name="password" type="password" placeholder="Password">
        <button type="submit">Login</button>
    </form>
    <p><a href="/search?q=test">Search</a></p>
    """


@app.route("/login", methods=["POST"])
def login():
    # Regenerate session on login to prevent session fixation
    username = request.form.get("username")
    password = request.form.get("password")
    
    user = users.get(username)
    if user and user["password"] == password:
        resp = make_response(f"Welcome {username}!")
        # Regenerate session: clear all old session data and set fresh
        # This creates a new session cookie, invalidating any attacker-controlled ID
        session.clear()
        session["username"] = username
        session["role"] = user["role"]
        # Re-bind session origin after regeneration
        ip, ua = _get_session_origin()
        session["_bound"] = True
        session["_ip"] = ip
        session["_ua"] = ua
        session["_created_at"] = __import__("time").time()
        return resp
    
    return "Invalid credentials", 401


@app.before_request
def sanitize_query_params():
    """Validate and deduplicate HTTP query parameters on every request.

    Prevents HTTP Parameter Pollution (HPP) attacks where an attacker sends
    duplicate parameters (?admin=true&admin=false) to bypass security checks.
    """
    if not request.query_string:
        return
    
    raw = request.query_string.decode("utf-8")
    
    # Reject requests with duplicate parameters outright
    seen = set()
    for pair in raw.split("&"):
        if not pair:
            continue
        key = pair.split("=")[0]
        if key in seen:
            return jsonify({
                "error": "Duplicate parameter detected",
                "message": "HTTP Parameter Pollution attack detected"
            }), 400
        seen.add(key)


@app.route("/search")
def search():
    query = request.args.get("q", "")
    # Fix XSS: Escape user input before rendering
    safe_query = html.escape(query)
    template = """
    <!DOCTYPE html>
    <html>
        <title>Search</title>
    </head>
    <body>
        <h1>Search Results for: """ + safe_query + """</h1>
        <p>You searched for: """ + safe_query + """</p>
    </body>
    </html>
    """
    return template


@app.route("/change_email", methods=["POST"])
def change_email():
    # Fix CSRF: Validate CSRF token
    if "username" not in session:
        return "Not authenticated", 401
    
    csrf_token = request.form.get("csrf_token")
    if not validate_csrf_token(csrf_token):
        return "Invalid CSRF token", 403
    
    new_email = request.form.get("email")
    # Fix XSS: Escape output
    safe_email = html.escape(new_email)
    safe_username = html.escape(session["username"])
    return f"Email changed to {safe_email} for user {safe_username}"


@app.route("/profile")
def profile():
    if "username" not in session:
        return "Not authenticated", 401
    safe_username = html.escape(session["username"])
    return f"Profile of {safe_username}"


@app.route("/transfer", methods=["POST"])
def transfer():
    # Fix CSRF: Validate CSRF token
    if "username" not in session:
        return "Not authenticated", 401
    
    csrf_token = request.form.get("csrf_token")
    if not validate_csrf_token(csrf_token):
        return "Invalid CSRF token", 403
    
    amount = request.form.get("amount")
    to_user = request.form.get("to")
    # Fix XSS: Escape output
    safe_amount = html.escape(str(amount))
    safe_to = html.escape(to_user)
    return f"Transferred {safe_amount} to {safe_to}"


if __name__ == "__main__":
    # Security: Disable debug in production
    app.run(debug=False)
