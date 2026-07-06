import jwt
from flask import Flask, request, jsonify

app = Flask(__name__)
SECRET = "super-secret-key"

@app.route("/api/protected")
def protected():
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    if not token:
        return jsonify({"error": "Missing token"}), 401
    try:
        data = jwt.decode(token, SECRET, algorithms=["HS256"])
    except jwt.InvalidTokenError:
        return jsonify({"error": "Invalid token"}), 401
    return jsonify({"user": data["user"]})

if __name__ == "__main__":
    app.run()
