import re
from flask import Flask, request, abort

app = Flask(__name__)

# Before: token passed as query parameter, e.g., /api/resource?session_token=abc123
# After: token should be passed via Authorization header or secure cookie

def secure_get_token():
    # Attempt to read from Authorization header (Bearer token)
    auth_header = request.headers.get('Authorization', '')
    if auth_header.startswith('Bearer '):
        return auth_header[7:]
    # Fallback to secure cookie (HttpOnly, Secure, SameSite)
    token = request.cookies.get('session_token')
    if token:
        return token
    # Reject if token appears in URL (vulnerable)
    if 'session_token' in request.args:
        # Log or abort with error
        abort(400, 'Session token in URL is not allowed. Use Authorization header or secure cookie.')
    return None

@app.route('/api/resource')
def get_resource():
    token = secure_get_token()
    if not token:
        abort(401, 'Missing or invalid session token')
    # Validate token... (e.g., check against DB)
    # If valid, proceed; else 401
    return {"message": "Resource accessed securely"}

if __name__ == '__main__':
    # Ensure HTTPS in production
    app.run(ssl_context='adhoc')  # for demo only
