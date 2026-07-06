from flask import Flask, request, jsonify
import db  # assume database module

app = Flask(__name__)

def get_current_user():
    # Simple token auth; in production use JWT or session
    auth_header = request.headers.get('Authorization')
    if not auth_header or not auth_header.startswith('Bearer '):
        return None
    token = auth_header.split(' ')[1]
    # Validate token (e.g., decode JWT, lookup session)
    user = db.query("SELECT id FROM users WHERE token = ?", (token,)).fetchone()
    return user['id'] if user else None

@app.route("/api/user/<user_id>")
def get_user_profile(user_id):
    current_user = get_current_user()
    if current_user is None:
        return jsonify({'error': 'Unauthorized'}), 401
    # Authorization check: only allow if user_id matches current user
    if str(current_user) != user_id:
        return jsonify({'error': 'Forbidden'}), 403
    # Use parameterized query to prevent SQL injection
    user = db.query("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    if user is None:
        return jsonify({'error': 'Not found'}), 404
    return jsonify(user)

if __name__ == "__main__":
    app.run()
