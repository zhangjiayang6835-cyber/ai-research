from flask import Flask, request, jsonify
import secrets
import time
from database import db  # 假设数据库对象已定义

app = Flask(__name__)

# 存储重置 token 及其过期时间
reset_tokens = {}  # email -> {'token': str, 'expires_at': float}

TOKEN_EXPIRY_SECONDS = 15 * 60  # 15 分钟

@app.route("/api/reset-password", methods=["POST"])
def reset_password():
    email = request.json.get("email")
    if not email:
        return jsonify({"error": "Email is required"}), 400

    # 生成安全的随机 token
    token = secrets.token_urlsafe(32)
    expires_at = time.time() + TOKEN_EXPIRY_SECONDS
    reset_tokens[email] = {"token": token, "expires_at": expires_at}

    # 发送邮件... (省略)
    # 实际生产环境中应通过邮件服务发送链接: /confirm-reset?email=...&token=...
    return jsonify({"message": "Reset link sent"})

@app.route("/api/confirm-reset", methods=["POST"])
def confirm_reset():
    email = request.json.get("email")
    token = request.json.get("token")
    new_password = request.json.get("new_password")

    if not all([email, token, new_password]):
        return jsonify({"error": "Missing required fields"}), 400

    # 查找存储的记录
    record = reset_tokens.get(email)
    if not record:
        return jsonify({"error": "No reset request found"}), 400

    # 验证 token 是否匹配且未过期
    if record["token"] == token and time.time() < record["expires_at"]:
        # 防止重复使用 token
        del reset_tokens[email]
        # 更新密码（实际中应使用哈希密码）
        db.execute("UPDATE users SET password = ? WHERE email = ?", (new_password, email))
        return jsonify({"success": True})
    elif record["token"] == token and time.time() >= record["expires_at"]:
        # token 过期，清理
        del reset_tokens[email]
        return jsonify({"error": "Token expired"}), 400
    else:
        return jsonify({"error": "Invalid token"}), 400

if __name__ == "__main__":
    app.run()
