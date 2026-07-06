import re
from flask import request, jsonify

def get_session_token():
    """
    Securely retrieve session token from Authorization header.
    This replaces the vulnerable practice of passing tokens via URL query parameters.
    """
    # Vulnerable approach (DO NOT USE):
    # token = request.args.get('token')

    # Secure approach: Extract token from the Authorization header (Bearer scheme)
    auth_header = request.headers.get('Authorization', '')
    match = re.match(r'^Bearer\s+(.+)$', auth_header, re.IGNORECASE)
    if not match:
        # If header is missing or malformed, return None (caller should handle)
        return None
    token = match.group(1)
    return token

# Example usage in a Flask endpoint:
# @app.route('/api/data')
# def get_data():
#     token = get_session_token()
#     if not token:
#         return jsonify({'error': 'Unauthorized'}), 401
#     # Validate token (e.g., JWT verification) and proceed
#     return jsonify({'data': 'secure response'})
