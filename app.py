import jwt
from flask import Flask, request, jsonify

app = Flask(__name__)
SECRET = "super-secret-key"

@app.route("/api/protected")
def protected():
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        return jsonify({"error": "Missing or invalid Authorization header"}), 401
    
    token = auth_header.replace("Bearer ", "")
    
    try:
        # Force HS256 algorithm and reject "none" algorithm
        data = jwt.decode(token, SECRET, algorithms=["HS256"])
        return jsonify({"user": data["user"]})
    except jwt.ExpiredSignatureError:
        return jsonify({"error": "Token has expired"}), 401
    except jwt.InvalidTokenError:
        return jsonify({"error": "Invalid token"}), 401

if __name__ == "__main__":
    app.run()
