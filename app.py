from flask import Flask, request, jsonify
import secrets
import time
import hashlib

app = Flask(__name__)
reset_tokens = {}

@app.route("/api/reset-password", methods=["POST"])
def reset_password():
    email = request.json["email"]
    # Fix: use cryptographically secure random token
    token = secrets.token_urlsafe(32)
    # Store token and expiration (15 minutes from now)
    reset_tokens[email] = {
        "token": token,
        "expiry": time.time() + 900  # 15 minutes
    }
    # Send email (omitted for brevity)
    return jsonify({"message": "Reset link sent"})

@app.route("/api/confirm-reset", methods=["POST"])
def confirm_reset():
    email = request.json["email"]
    token = request.json["token"]
    new_password = request.json["new_password"]
    
    # Check if token exists and is not expired
    stored = reset_tokens.get(email)
    if stored is None or stored["token"] != token:
        return jsonify({"error": "Invalid token"}), 400
    
    if time.time() > stored["expiry"]:
        # Token expired, remove it and return error
        del reset_tokens[email]
        return jsonify({"error": "Token expired"}), 400
    
    # Update password in database
    db.execute("UPDATE users SET password = ? WHERE email = ?", (new_password, email))
    # Clean up used token
    del reset_tokens[email]
    return jsonify({"success": True})

if __name__ == "__main__":
    app.run(debug=True)
