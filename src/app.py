from flask import Flask, make_response

app = Flask(__name__)

@app.route('/withdrawal')
def withdrawal():
    response = make_response("<h1>Asset Withdrawal Page</h1>")
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['Content-Security-Policy'] = "frame-ancestors 'none'"
    return response

if __name__ == '__main__':
    app.run(debug=True)