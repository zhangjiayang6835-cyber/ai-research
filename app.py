from flask import Flask, request, jsonify, session
from flask_wtf.csrf import CSRFProtect, generate_csrf

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-here'  # Change to a secure random key in production

# Enable CSRF protection globally
csrf = CSRFProtect(app)

# Simulated database (replace with actual DB connection)
class FakeDB:
    def execute(self, query, params):
        # In production, use a real database library
        pass

db = FakeDB()

@app.route("/api/update-email", methods=["POST"])
def update_email():
    # CSRF protection is automatically checked by CSRFProtect.
    # The token must be provided via the X-CSRFToken header or the `csrf_token` form field.
    user_id = request.form.get("user_id")
    new_email = request.form.get("email")
    if not user_id or not new_email:
        return jsonify({"error": "Missing required fields"}), 400
    db.execute("UPDATE users SET email = ? WHERE id = ?", (new_email, user_id))
    return jsonify({"success": True})

@app.route("/api/csrf-token", methods=["GET"])
def get_csrf_token():
    # Endpoint for clients to obtain a CSRF token
    token = generate_csrf()
    return jsonify({"csrf_token": token})

@app.errorhandler(400)
def bad_request(e):
    return jsonify({"error": "Bad request"}), 400

@app.errorhandler(403)
def forbidden(e):
    return jsonify({"error": "CSRF token missing or invalid"}), 403

if __name__ == "__main__":
    app.run(debug=True)
