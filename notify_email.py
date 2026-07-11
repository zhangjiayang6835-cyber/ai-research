--- app.py ---
from flask import Flask, render_template_string, request, redirect, url_for, make_response

app = Flask(__name__)

@app.route('/withdraw')
def withdraw():
    # Add X-Frame-Options header to prevent clickjacking
    response = make_response(render_template_string('''
        <h1>Withdraw Crypto</h1>
        <form action="/process_withdraw" method="post">
            <input type="text" name="amount" placeholder="Amount">
            <button type="submit">Confirm Withdrawal</button>
        </form>
    '''))
    response.headers['X-Frame-Options'] = 'DENY'
    return response

@app.route('/process_withdraw', methods=['POST'])
def process_withdraw():
    amount = request.form.get('amount')
    # Process withdrawal logic here
    return redirect(url_for('withdraw'))

if __name__ == '__main__':
    app.run(debug=True)