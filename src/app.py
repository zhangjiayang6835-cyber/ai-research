from flask import Flask, request, render_template_string, make_response, session, jsonify
import sqlite3
import secrets
import html
from urllib.parse import parse_qs

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)

@app.after_request
def add_security_headers(response):
    response.headers['X-Frame-Options'] = 'DENY'
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

if __name__ == '__main__':
    # Security: Disable debug in production
    app.run(debug=False)