from flask import Flask, request, jsonify

app = Flask(__name__)

@app.after_request
def add_csp_header(response):
    csp_policy = (
        "default-src 'self'; "
        "script-src 'self'; "
        "style-src 'self'; "
        "img-src 'self'; "
        "font-src 'self'; "
        "connect-src 'self'; "
        "frame-ancestors 'none'; "
        "base-uri 'self'; "
        "form-action 'self'"
    )
    response.headers['Content-Security-Policy'] = csp_policy
    return response

@app.route('/')
def home():
    return jsonify({'message': 'CSP header is now set!'})

if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=8080)