from flask import Flask, request, session, jsonify
import os

app = Flask(__name__)
app.secret_key = "dev-secret"  # In production, use a secure random key

# Assume db is defined elsewhere (e.g., from database import db)
# from database import db

@app.route("/api/login", methods=["POST"])
def login():
    username = request.json.get("username")
    password = request.json.get("password")

    # Fix: Do not accept client-provided session ID
    # if "session_id" in request.json:
    #     session.sid = request.json["session_id"]

    # Use parameterized queries to prevent SQL injection (assumed)
    user = db.execute("SELECT * FROM users WHERE username = ? AND password = ?", (username, password)).fetchone()
    if user:
        # Fix: Regenerate session ID to prevent session fixation
        session.regenerate()
        session["user_id"] = user["id"]
        session["role"] = user["role"]
        return jsonify({"success": True, "session_id": session.sid})
    return jsonify({"error": "Login failed"}), 401

if __name__ == "__main__":
    app.run(debug=True)