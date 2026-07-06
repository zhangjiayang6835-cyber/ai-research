from flask import Flask, request, abort, session, jsonify

app = Flask(__name__)
app.secret_key = 'supersecretkey'  # In production, use environment variable

# Assume user authentication sets session['user_id']

@app.route('/profile/<int:user_id>', methods=['GET'])
def get_profile(user_id):
    # Check authentication
    if 'user_id' not in session:
        abort(401, description="Unauthorized")
    # IDOR fix: only allow access to own profile
    if session['user_id'] != user_id:
        abort(403, description="Forbidden: You can only view your own profile")
    # Fetch and return profile data (simulated)
    profile_data = {
        'user_id': user_id,
        'username': 'user_' + str(user_id),
        'email': f'user{user_id}@example.com'
    }
    return jsonify(profile_data)

if __name__ == '__main__':
    app.run()
