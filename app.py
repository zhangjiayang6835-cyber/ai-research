from flask import Flask, request, jsonify
import sqlite3

app = Flask(__name__)

# 白名单：只允许更新这些字段
ALLOWED_FIELDS = {'email', 'display_name'}

@app.route("/api/user/update", methods=["POST"])
def update_user():
    data = request.json
    if not data:
        return jsonify({"error": "No data provided"}), 400

    user_id = data.get("user_id")
    if not user_id:
        return jsonify({"error": "user_id is required"}), 400

    # 过滤出白名单字段
    update_data = {k: v for k, v in data.items() if k in ALLOWED_FIELDS and k != "user_id"}
    if not update_data:
        return jsonify({"error": "No valid fields to update"}), 400

    # 构建SQL更新语句
    fields = ", ".join(f"{k} = ?" for k in update_data.keys())
    values = list(update_data.values())

    conn = sqlite3.connect("app.db")
    try:
        conn.execute(f"UPDATE users SET {fields} WHERE id = ?", (*values, user_id))
        conn.commit()
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        conn.close()

    return jsonify({"success": True})
