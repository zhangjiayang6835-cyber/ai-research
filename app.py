from flask import Flask, request, jsonify
import sqlite3

app = Flask(__name__)

ALLOWED_FIELDS = {'email', 'display_name'}

@app.route("/api/user/update", methods=["POST"])
def update_user():
    data = request.json
    if not data:
        return jsonify({"error": "No data provided"}), 400

    user_id = data.get("user_id")
    if not user_id:
        return jsonify({"error": "Missing user_id"}), 400

    # Filter to only allowed fields
    safe_data = {k: v for k, v in data.items() if k in ALLOWED_FIELDS}
    if not safe_data:
        return jsonify({"error": "No updatable fields provided"}), 400

    fields = ", ".join(f"{k} = ?" for k in safe_data.keys())
    values = list(safe_data.values())
    
    conn = sqlite3.connect("app.db")
    try:
        conn.execute(f"UPDATE users SET {fields} WHERE id = ?", (*values, user_id))
        conn.commit()
    except Exception as e:
        conn.rollback()
        return jsonify({"error": str(e)}), 500
    finally:
        conn.close()

    return jsonify({"success": True})
