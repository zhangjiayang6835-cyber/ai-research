from flask import Flask, request, jsonify
import sqlite3

app = Flask(__name__)

ALLOWED_FIELDS = {'email', 'display_name'}

@app.route("/api/user/update", methods=["POST"])
def update_user():
    data = request.json
    user_id = data.get("user_id")
    if not user_id:
        return jsonify({"success": False, "error": "Missing user_id"}), 400

    # Filter only allowed fields
    update_data = {k: v for k, v in data.items() if k in ALLOWED_FIELDS}
    if not update_data:
        return jsonify({"success": True})  # nothing to update

    # Build parameterized query
    fields = ', '.join(f"{k} = ?" for k in update_data.keys())
    values = list(update_data.values())
    values.append(user_id)

    conn = sqlite3.connect("app.db")
    conn.execute(f"UPDATE users SET {fields} WHERE id = ?", values)
    conn.commit()
    conn.close()

    return jsonify({"success": True})
