from flask import Flask, request, jsonify
import sqlite3

app = Flask(__name__)

# 初始化数据库（仅用于演示，实际应分开管理）
def init_db():
    conn = sqlite3.connect('shop.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (id INTEGER PRIMARY KEY, balance REAL)''')
    c.execute('''CREATE TABLE IF NOT EXISTS orders
                 (id INTEGER PRIMARY KEY, user_id INTEGER, amount REAL)''')
    conn.commit()
    conn.close()

init_db()

@app.route('/api/refund', methods=['POST'])
def refund():
    data = request.json
    user_id = data.get('user_id')
    amount = data.get('amount')
    order_id = data.get('order_id')  # 假设前端传入订单ID

    # 参数校验
    if not user_id or not amount or not order_id:
        return jsonify({'success': False, 'error': 'Missing required fields'}), 400

    try:
        amount = float(amount)
        user_id = int(user_id)
        order_id = int(order_id)
    except (ValueError, TypeError):
        return jsonify({'success': False, 'error': 'Invalid input types'}), 400

    # 校验金额必须为正数
    if amount <= 0:
        return jsonify({'success': False, 'error': 'Refund amount must be positive'}), 400

    conn = sqlite3.connect('shop.db')
    cursor = conn.cursor()

    # 获取订单信息
    cursor.execute('SELECT amount FROM orders WHERE id = ? AND user_id = ?', (order_id, user_id))
    row = cursor.fetchone()
    if not row:
        conn.close()
        return jsonify({'success': False, 'error': 'Order not found'}), 404

    order_amount = row[0]
    # 确保退款金额不超过原订单金额
    if amount > order_amount:
        conn.close()
        return jsonify({'success': False, 'error': 'Refund amount exceeds order amount'}), 400

    # 执行退款（增加用户余额）
    cursor.execute('UPDATE users SET balance = balance + ? WHERE id = ?', (amount, user_id))
    conn.commit()
    conn.close()

    return jsonify({'success': True, 'refunded': amount})

if __name__ == '__main__':
    app.run(debug=True)