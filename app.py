from flask import Flask, request, jsonify
import secrets
import time

app = Flask(__name__)

# In-memory store for reset tokens: email -> (token, expiry_timestamp)
reset_tokens = {}

TOKEN_EXPIRY_SECONDS = 15 * 60  # 15 minutes

@app.route("/api/reset-password", methods=["POST"])
def reset_password():
    email = request.json.get("email")
    if not email:
        return jsonify({"error": "Email is required"}), 400

    # Generate a cryptographically secure random token
    token = secrets.token_urlsafe(32)
    expiry = time.time() + TOKEN_EXPIRY_SECONDS
    reset_tokens[email] = (token, expiry)

    # Send email with reset link (omitted for brevity)
    # send_reset_email(email, token)
    return jsonify({"message": "Reset link sent"})

@app.route("/api/confirm-reset", methods=["POST"])
def confirm_reset():
    email = request.json.get("email")
    token = request.json.get("token")
    new_password = request.json.get("new_password")

    if not email or not token or not new_password:
        return jsonify({"error": "Missing fields"}), 400

    stored = reset_tokens.get(email)
    if not stored:
        return jsonify({"error": "Invalid token"}), 400

    stored_token, expiry = stored

    # Check token validity and expiration
    if stored_token != token:
        return jsonify({"error": "Invalid token"}), 400
    if time.time() > expiry:
        # Clean up expired token
        del reset_tokens[email]
        return jsonify({"error": "Token expired"}), 400

    # Update password in database (example using SQLite, adapt as needed)
    # db.execute("UPDATE users SET password = ? WHERE email = ?", (new_password, email))
    # For demonstration, we just print
    print(f"Password updated for {email}")

    # Remove used token
    del reset_tokens[email]
    return jsonify({"success": True})

if __name__ == "__main__":
    app.run(debug=True)
