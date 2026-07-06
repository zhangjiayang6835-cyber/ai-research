from flask import Flask, request, jsonify, session
import secrets

app = Flask(__name__)
app.secret_key = 'your-secret-key'  # Replace with a strong secret key

def generate_csrf_token():
    if '_csrf_token' not in session:
        session['_csrf_token'] = secrets.token_hex(32)
    return session['_csrf_token']

@app.route('/api/csrf-token', methods=['GET'])
def get_csrf_token():
    return jsonify({'csrf_token': generate_csrf_token()})

@app.route('/api/update-email', methods=['POST'])
def update_email():
    # CSRF validation
    request_token = request.form.get('csrf_token') or request.headers.get('X-CSRF-Token')
    session_token = session.get('_csrf_token')
    if not request_token or not session_token or request_token != session_token:
        return jsonify({'error': 'CSRF validation failed'}), 403

    user_id = request.form.get('user_id')
    new_email = request.form.get('email')
    if not user_id or not new_email:
        return jsonify({'error': 'Missing parameters'}), 400

    # Simulate database update
    # db.execute("UPDATE users SET email = ? WHERE id = ?", (new_email, user_id))
    return jsonify({'success': True})

if __name__ == '__main__':
    app.run()