from flask import Flask, request, jsonify
from pymongo import MongoClient

app = Flask(__name__)
db = MongoClient()["app"]

def sanitize_mongo_field(value):
    """
    Rejects values that could be used for NoSQL injection.
    Only allows plain strings (no dict, list, or values containing $ or .).
    """
    if not isinstance(value, str):
        raise ValueError("Invalid input type")
    if '$' in value or '.' in value:
        raise ValueError("Input contains invalid characters")
    return value

@app.route("/api/login", methods=["POST"])
def login():
    data = request.get_json(silent=True)
    if not data or "username" not in data or "password" not in data:
        return jsonify({"error": "Missing credentials"}), 400

    try:
        username = sanitize_mongo_field(data["username"])
        password = sanitize_mongo_field(data["password"])
    except ValueError:
        return jsonify({"error": "Invalid input"}), 400

    user = db.users.find_one({
        "username": username,
        "password": password
    })
    if user:
        return jsonify({"token": "session_token"})
    return jsonify({"error": "Login failed"}), 401

if __name__ == "__main__":
    app.run()
