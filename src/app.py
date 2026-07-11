import os
from flask import Flask, request, render_template_string, make_response, session
import sqlite3
import secrets
import html

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)

# ---------------------------------------------------------------------------
# Fix for issue #963 — Host Header Injection → Password Reset Poisoning
# ---------------------------------------------------------------------------
# Trusted host whitelist.  Only hosts in this list are allowed to be used
# in generated URLs (password reset links, redirects, etc.).
TRUSTED_HOSTS = frozenset(
    h.strip().lower()
    for h in os.environ.get(
        "TRUSTED_HOSTS",
        "localhost,127.0.0.1,0.0.0.0,app.example.com,api.example.com",
    ).split(",")
    if h.strip()
)


def get_safe_base_url() -> str:
    """Return a safe base URL built from a trusted host.

    Never uses the user-supplied Host header for URL generation.
    Falls back to the default trusted host if the request Host
    is not whitelisted.
    """
    if request and request.host:
        host = request.host.lower().rstrip(":")
        if host in TRUSTED_HOSTS:
            scheme = request.scheme if request.scheme else "https"
            return f"{scheme}://{host}"
    return "https://app.example.com"


@app.before_request
def validate_host_header():
    """Reject requests whose Host header is not in the whitelist.

    Prevents Host header injection attacks (e.g. password reset link
    poisoning, cache poisoning).
    """
    if not request.host:
        return None
    host = request.host.lower().rstrip(":")
    if host not in TRUSTED_HOSTS:
        return make_response(
            "<h1>400 Bad Request</h1><p>Invalid Host header.</p>", 400
        )


@app.after_request
def security_headers(response):
    """Add anti-tampering headers on every response."""
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    return response

# Simulated user database
users = {
    'admin': {'password': 'admin123', 'role': 'admin'},
    'user1': {'password': 'user123', 'role': 'user'}
}

# CSRF token generation and validation
def generate_csrf_token():
    if 'csrf_token' not in session:
        session['csrf_token'] = secrets.token_urlsafe(32)
    return session['csrf_token']

def validate_csrf_token(token):
    return token == session.get('csrf_token')

# Make csrf_token available in templates
app.jinja_env.globals['csrf_token'] = generate_csrf_token

@app.route('/')
def index():
    return '''
    <h1>AI Research Platform</h1>
    <form action="/login" method="POST">
        <input name="username" placeholder="Username">
        <input name="password" type="password" placeholder="Password">
        <button type="submit">Login</button>
    </form>
    <p><a href="/search?q=test">Search</a></p>

@app.route('/login', methods=['POST'])
def login():
    # Regenerate session on login to prevent session fixation
    username = request.form.get('username')
    password = request.form.get('password')
    
        user = users[username]
        if user['password'] == password:
            resp = make_response(f"Welcome {username}!")
            # Use secure session instead of plain cookie
            session.clear()
            session['username'] = username
            session['role'] = user['role']
            return resp
    
    return "Invalid credentials", 401
@app.route('/search')
def search():
    query = request.args.get('q', '')
    # Fix XSS: Escape user input before rendering
    safe_query = html.escape(query)
    template = '''
    <!DOCTYPE html>
    <html>
        <title>Search</title>
    </head>
    <body>
        <h1>Search Results for: ''' + safe_query + '''</h1>
        <p>You searched for: ''' + safe_query + '''</p>
    </body>
    </html>
    '''

@app.route('/change_email', methods=['POST'])
def change_email():
    # Fix CSRF: Validate CSRF token
    if 'username' not in session:
        return "Not authenticated", 401
    
    csrf_token = request.form.get('csrf_token')
    if not validate_csrf_token(csrf_token):
        return "Invalid CSRF token", 403
    
    new_email = request.form.get('email')
    # Fix XSS: Escape output
    safe_email = html.escape(new_email)
    safe_username = html.escape(session['username'])
    return f"Email changed to {safe_email} for user {safe_username}"

@app.route('/profile')
def profile():
    if 'username' not in session:
        return "Not authenticated", 401
    safe_username = html.escape(session['username'])
    return f"Profile of {safe_username}"

@app.route('/transfer', methods=['POST'])
def transfer():
    # Fix CSRF: Validate CSRF token
    if 'username' not in session:
        return "Not authenticated", 401
    
    csrf_token = request.form.get('csrf_token')
    if not validate_csrf_token(csrf_token):
        return "Invalid CSRF token", 403
    
    amount = request.form.get('amount')
    to_user = request.form.get('to')
    # Fix XSS: Escape output
    safe_amount = html.escape(str(amount))
    safe_to = html.escape(to_user)
    return f"Transferred {safe_amount} to {safe_to}"

@app.route('/password_reset', methods=['POST'])
def password_reset():
    """Generate a password reset link using a TRUSTED host.

    Never uses the user-supplied Host header for URL generation.
    This prevents attackers from poisoning the reset link by sending
    a malicious Host header.
    """
    token = secrets.token_urlsafe(32)
    base = get_safe_base_url()
    reset_url = f"{base}/reset?token={token}"
    return {"reset_url": reset_url, "message": "Password reset email sent"}


if __name__ == '__main__':
    # Security: Disable debug in production
    app.run(debug=False)