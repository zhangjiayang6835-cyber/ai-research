from flask import Flask, request, session, jsonify
import os

app = Flask(__name__)
app.secret_key = "dev-secret"

@app.route("/api/login", methods=["POST"])
def login():
    username = request.json["username"]
    password = request.json["password"]
    
    # Fix: Do not accept client-provided session ID
    # Removed the buggy session_id assignment
    
    user = db.execute("SELECT * FROM users WHERE username = ? AND password = ?", (username, password)).fetchone()
    if user:
        # Fix: Regenerate session after successful login
        session.regenerate()
        session["user_id"] = user["id"]
        session["role"] = user["role"]
        return jsonify({"success": True, "session_id": session.sid})
    return jsonify({"error": "Login failed"}), 401