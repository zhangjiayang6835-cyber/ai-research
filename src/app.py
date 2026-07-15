from flask import Flask, request, render_template_string, make_response, session, jsonify, redirect, url_for
import sqlite3
import secrets
import html
import hmac
from urllib.parse import parse_qs, urlparse

app = Flask(__name__)

# Secure session cookie configuration
app.config.update(
    SECRET_KEY=secrets.token_hex(32),
    SERVER_NAME='example.com',
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
)

# Trusted hosts — only these are allowed in Host header
TRUSTED_HOSTS = frozenset({
    "example.com",
    "www.example.com",
    "api.example.com",
    "app.example.com",
})

# Canonical host used for generating absolute URLs (never client-supplied)
CANONICAL_HOST = "example.com"


@app.before_request
def validate_host_header():
    """Reject requests whose Host header is not trusted."""
    host = request.host
    if ':' in host:
        host = host.split(':')[0]
    if host.lower() not in TRUSTED_HOSTS:
        return jsonify({"error": "Invalid Host header"}), 400


@app.after_request
def add_security_headers(response):
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-Content-Type-Options'] = 'nosniff'
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
    stored = session.get('csrf_token')
    if not stored or not token:
        return False
    return hmac.compare_digest(token, stored)

# Make csrf_token available in templates
app.jinja_env.globals['csrf_token'] = generate_csrf_token


# =============================================================================
# Password Reset (secure — uses CANONICAL_HOST, never client Host header)
# =============================================================================

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'GET':
        csrf = generate_csrf_token()
        return render_template_string('''
            <h1>Reset Password</h1>
            <form method="POST">
                <input type="hidden" name="csrf_token" value="{{ csrf }}">
                <input name="email" placeholder="Your email">
                <button type="submit">Send Reset Link</button>
            </form>
        ''', csrf=csrf)

    # POST — validate CSRF then generate reset link
    csrf_token = request.form.get('csrf_token', '')
    if not validate_csrf_token(csrf_token):
        return "Invalid CSRF token", 403

    email = request.form.get('email', '')
    reset_token = secrets.token_urlsafe(48)
    reset_url = f"https://{CANONICAL_HOST}/reset?token={reset_token}"

    return jsonify({
        "message": "If an account exists, a reset link has been sent.",
        "reset_url": reset_url,
    }), 200


@app.route('/reset', methods=['GET', 'POST'])
def reset_password():
    if request.method == 'GET':
        token = request.args.get('token', '')
        if not token:
            return "Missing token", 400
        csrf = generate_csrf_token()
        return render_template_string('''
            <h1>Set New Password</h1>
            <form method="POST">
                <input type="hidden" name="csrf_token" value="{{ csrf }}">
                <input type="hidden" name="token" value="{{ token }}">
                <input name="password" type="password" placeholder="New password">
                <button type="submit">Reset</button>
            </form>
        ''', csrf=csrf, token=token)

    # POST — validate CSRF + token, then update password
    csrf_token = request.form.get('csrf_token', '')
    if not validate_csrf_token(csrf_token):
        return "Invalid CSRF token", 403

    token = request.form.get('token', '')
    new_password = request.form.get('password', '')
    if not token or not new_password:
        return "Missing fields", 400

    return jsonify({"message": "Password has been reset."}), 200


# =============================================================================
# Routes
# =============================================================================

@app.route('/')
def index():
    return '''
    <h1>AI Research Platform</h1>
    <form action="/login" method="POST">
        <input name="username" placeholder="Username">
        <input name="password" type="password" placeholder="Password">
        <button type="submit">Login</button>
    </form>
    <p><a href="/forgot_password">Forgot password?</a></p>
    <p><a href="/search?q=test">Search</a></p>
    '''

@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username')
    password = request.form.get('password')

    if username in users and users[username]['password'] == password:
        session.clear()
        session['username'] = username
        session['role'] = users[username]['role']
        return make_response(f"Welcome {username}!")

    return "Invalid credentials", 401


@app.before_request
def sanitize_query_params():
    if not request.query_string:
        return
    raw = request.query_string.decode('utf-8')
    seen = set()
    for pair in raw.split('&'):
        if not pair:
            continue
        key = pair.split('=')[0]
        if key in seen:
            return jsonify({
                'error': 'Duplicate parameter detected',
                'message': 'HTTP Parameter Pollution attack detected'
            }), 400
        seen.add(key)


@app.route('/search')
def search():
    query = request.args.get('q', '')
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
    return template

@app.route('/change_email', methods=['POST'])
def change_email():
    if 'username' not in session:
        return "Not authenticated", 401
    csrf_token = request.form.get('csrf_token')
    if not validate_csrf_token(csrf_token):
        return "Invalid CSRF token", 403
    new_email = request.form.get('email')
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
    if 'username' not in session:
        return "Not authenticated", 401
    csrf_token = request.form.get('csrf_token')
    if not validate_csrf_token(csrf_token):
        return "Invalid CSRF token", 403
    amount = request.form.get('amount')
    to_user = request.form.get('to')
    safe_amount = html.escape(str(amount))
    safe_to = html.escape(to_user)
    return f"Transferred {safe_amount} to {safe_to}"

if __name__ == '__main__':
    app.run(debug=False)
