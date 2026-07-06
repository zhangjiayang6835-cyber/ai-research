from flask import Flask, request, jsonify
import sqlite3

app = Flask(__name__)

DATABASE = "shop.db"

def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    conn.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            balance REAL NOT NULL DEFAULT 0
        )
    ''')
    conn.execute('''
        CREATE TABLE IF NOT EXISTS orders (
            id INTEGER PRIMARY KEY,
            user_id INTEGER NOT NULL,
            amount REAL NOT NULL,
            refunded REAL NOT NULL DEFAULT 0,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    ''')
    conn.commit()
    conn.close()

@app.route("/api/refund", methods=["POST"])
def refund():
    data = request.get_json()
    if not data:
        return jsonify({"error": "Invalid JSON"}), 400

    user_id = data.get("user_id")
    amount = data.get("amount")
    order_id = data.get("order_id")

    if not all([user_id, amount, order_id]):
        return jsonify({"error": "Missing required fields: user_id, amount, order_id"}), 400

    try:
        amount = float(amount)
    except (TypeError, ValueError):
        return jsonify({"error": "Invalid amount"}), 400

    if amount <= 0:
        return jsonify({"error": "Amount must be positive"}), 400

    conn = get_db()
    try:
        # Fetch order and validate
        order = conn.execute(
            "SELECT id, user_id, amount, refunded FROM orders WHERE id = ? AND user_id = ?",
            (order_id, user_id)
        ).fetchone()

        if not order:
            return jsonify({"error": "Order not found or does not belong to user"}), 404

        if amount > order["amount"] - order["refunded"]:
            return jsonify({"error": "Refund amount exceeds remaining order amount"}), 400

        # Perform refund: update user balance and order refunded amount
        conn.execute(
            "UPDATE users SET balance = balance + ? WHERE id = ?",
            (amount, user_id)
        )
        conn.execute(
            "UPDATE orders SET refunded = refunded + ? WHERE id = ?",
            (amount, order_id)
        )
        conn.commit()

        return jsonify({"success": True, "refunded": amount})

    except Exception as e:
        conn.rollback()
        return jsonify({"error": "Internal server error"}), 500
    finally:
        conn.close()

if __name__ == "__main__":
    init_db()
    app.run(debug=True)
