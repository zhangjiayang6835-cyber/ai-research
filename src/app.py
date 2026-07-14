from flask import Flask, request, render_template_string, make_response, session, jsonify
import sqlite3
import secrets
import html
from urllib.parse import parse_qs

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)

# ---------------------------------------------------------------------------
# Security headers — X-Frame-Options + CSP frame-ancestors on every response
# ---------------------------------------------------------------------------
@app.after_request
def add_security_headers(response):
    """Apply clickjacking protection to every HTTP response.

    Satisfies issue #1176: adds X-Frame-Options: DENY and
    Content-Security-Policy: frame-ancestors 'none' so the app cannot be
    embedded in an attacker-controlled iframe.
    """
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "script-src 'self'; "
        "style-src 'self' 'unsafe-inline'; "
        "frame-ancestors 'none'"
    )
    return response


# ---------------------------------------------------------------------------
# Simulated user database
# ---------------------------------------------------------------------------
users = {
    'admin': {'password': 'admin123', 'role': 'admin'},
    'user1': {'password': 'user123', 'role': 'user'}
}


# ---------------------------------------------------------------------------
# CSRF helpers
# ---------------------------------------------------------------------------
def generate_csrf_token():
    if 'csrf_token' not in session:
        session['csrf_token'] = secrets.token_urlsafe(32)
    return session['csrf_token']


def validate_csrf_token(token):
    return token == session.get('csrf_token')


app.jinja_env.globals['csrf_token'] = generate_csrf_token


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------
INDEX_TEMPLATE = """
<h1>AI Research Platform</h1>
<form action="/login" method="POST">
    <input name="username" placeholder="Username">
    <input name="password" type="password" placeholder="Password">
    <button type="submit">Login</button>
</form>
<p><a href="/search?q=test">Search</a></p>
"""


@app.route('/')
def index():
    return INDEX_TEMPLATE


@app.route('/login', methods=['POST'])
def login():
    # Regenerate session on login to prevent session fixation
    username = request.form.get('username')
    password = request.form.get('password')

    if username in users:
        user = users[username]
        if user['password'] == password:
            resp = make_response(f"Welcome {username}!")
            # Use secure session instead of plain cookie
            session.clear()
            session['username'] = username
            session['role'] = user['role']
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

    raw = request.query_string.decode('utf-8')

    # Reject requests with duplicate parameters outright
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


SEARCH_TEMPLATE = """
<!DOCTYPE html>
<html>
    <head><title>Search</title></head>
    <body>
        <h1>Search Results for: {{ query }}</h1>
        <p>You searched for: {{ query }}</p>
    </body>
</html>
"""


@app.route('/search')
def search():
    query = request.args.get('q', '')
    safe_query = html.escape(query)
    return render_template_string(SEARCH_TEMPLATE, query=safe_query)


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


# ---------------------------------------------------------------------------
# Crypto withdrawal route — protected against clickjacking (issue #1176)
# ---------------------------------------------------------------------------
WITHDRAW_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Crypto Withdrawal</title>
    <style>
        .warning { color: #b00020; font-weight: bold; }
        .error { color: red; }
    </style>
</head>
<body>
    <h2>Crypto Withdrawal</h2>
    <p class="warning">Warning: This is an irreversible action.</p>
    {% if error %}
    <p class="error">{{ error }}</p>
    {% endif %}
    <form action="/withdraw/crypto" method="POST" id="withdraw-form">
        <label>
            Wallet Address<br>
            <input type="text" name="address" value="{{ address or '' }}" required>
        </label><br><br>
        <label>
            Amount<br>
            <input type="number" step="0.000001" name="amount" value="{{ amount or '' }}" required>
        </label><br><br>
        <label>
            <input type="checkbox" name="confirm_withdraw" value="yes" required>
            I confirm this withdrawal is irreversible.
        </label><br><br>
        <button type="submit" id="confirm-btn" disabled>Confirm Withdrawal</button>
    </form>
    <script>
        // Button only enabled after user explicitly checks confirmation
        var form = document.getElementById('withdraw-form');
        var confirmBox = form.querySelector('input[name="confirm_withdraw"]');
        var btn = document.getElementById('confirm-btn');
        confirmBox.addEventListener('change', function() { btn.disabled = !confirmBox.checked; });
        // Final JS confirmation prompt as defense-in-depth
        form.addEventListener('submit', function(e) {
            if (!confirm('Confirm crypto withdrawal? This action cannot be undone.')) {
                e.preventDefault();
            }
        });
    </script>
</body>
</html>
"""


@app.route('/withdraw/crypto', methods=['GET', 'POST'])
def crypto_withdraw():
    """Crypto withdrawal endpoint with clickjacking-safe confirmation.

    Accepts only POST with an explicit confirm_withdraw='yes' checkbox.
    GET shows the confirmation form.
    """
    if 'username' not in session:
        return "Not authenticated", 401

    if request.method == 'POST':
        confirmed = request.form.get('confirm_withdraw')
        address = request.form.get('address', '').strip()
        amount = request.form.get('amount', '').strip()

        if confirmed != 'yes':
            return render_template_string(WITHDRAW_TEMPLATE,
                address=address, amount=amount,
                error="Please check the confirmation checkbox to proceed.")

        if not address or not amount:
            return render_template_string(WITHDRAW_TEMPLATE,
                address=address, amount=amount,
                error="Address and amount are required.")

        safe_user = html.escape(session['username'])
        safe_addr = html.escape(address)
        safe_amt = html.escape(amount)
        return render_template_string(
            "<h2>Withdrawal Initiated</h2>"
            "<p>User: {{ user }}</p>"
            "<p>Address: {{ addr }}</p>"
            "<p>Amount: {{ amt }}</p>"
            "<p>Confirm the transaction in your wallet to complete withdrawal.</p>",
            user=safe_user, addr=safe_addr, amount=safe_amt)

    # GET — show the withdrawal confirmation form
    return render_template_string(WITHDRAW_TEMPLATE)


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------
if __name__ == '__main__':
    app.run(debug=False)
