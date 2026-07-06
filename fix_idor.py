from flask import Flask, request, abort, session

app = Flask(__name__)

# Assume user_id is stored in session after login
def get_current_user_id():
    return session.get('user_id')

@app.route('/profile/<int:user_id>')
def view_profile(user_id):
    # Authenticate user
    current_user_id = get_current_user_id()
    if current_user_id is None:
        abort(401)  # Unauthorized
    
    # Authorize: only allow access to own profile
    if user_id != current_user_id:
        abort(403)  # Forbidden
    
    # Fetch and return profile data for user_id
    # ...
    return f"Profile data for user {user_id}"