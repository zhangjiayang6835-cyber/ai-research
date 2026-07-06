from flask import Flask, request, jsonify, session
import sqlite3

app = Flask(__name__)
app.secret_key = 'change-this-to-a-secure-random-key'

def get_db():
    conn = sqlite3.connect('database.db')
    return conn

@app.route("/api/user/<user_id>")
def get_user_profile(user_id):
    # Authentication: check if user is logged in
    if 'user_id' not in session:
        return jsonify({"error": "Unauthorized"}), 401
    
    # Authorization: ensure user can only access their own profile
    try:
        current_user_id = session['user_id']
        requested_user_id = int(user_id)
    except ValueError:
        return jsonify({"error": "Invalid user ID"}), 400
    
    if current_user_id != requested_user_id:
        return jsonify({"error": "Forbidden"}), 403
    
    # Use parameterized query to prevent SQL injection
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE id = ?", (requested_user_id,))
    user = cursor.fetchone()
    conn.close()
    
    if user is None:
        return jsonify({"error": "User not found"}), 404
    
    # Convert row to dictionary (assuming sqlite3.Row or similar)
    columns = [desc[0] for desc in cursor.description]
    user_dict = dict(zip(columns, user))
    return jsonify(user_dict)

if __name__ == '__main__':
    app.run(debug=True)