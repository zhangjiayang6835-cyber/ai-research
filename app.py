from flask import Flask, request, session, jsonify
import os

app = Flask(__name__
app.secret_key = "dev-secret"  # In production, use a secure environment variable

@app.route("/api/login", methods=["POST"])
def login():
    username = request.json["username"]
    password = request.json["password"]

    # Fix: Do not accept client-provided session ID
    # if "session_id" in request.json:
    #     session.sid = request.json["session_id"]

    user = db.execute("SELECT * FROM users WHERE username = ? AND password = ?", (username, password)).fetchone()
    if user:
        # Fix: Regenerate session ID after successful login
        session.regenerate()
        session["user_id"] = user["id"]
        session["role"] = user["role"]
        return jsonify({"success": True, "session_id": session.sid})
    return jsonify({"error": "Login failed"}), 401

if __name__ == "__main__":
    app.run()
