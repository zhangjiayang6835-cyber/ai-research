from flask import Flask, request, jsonify, session
import secrets

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)

# Bad practice: session token in URL
# Example URL: /data?token=abc123
# @app.route('/data')
# def get_data():
#     token = request.args.get('token')
#     # validate token...
#     return jsonify(data='secret')

# Good practice: use Authorization header with Bearer token
@app.route('/data')
def get_data():
    auth_header = request.headers.get('Authorization')
    if not auth_header or not auth_header.startswith('Bearer '):
        return jsonify(error='Missing or invalid token'), 401
    token = auth_header.split(' ')[1]
    # validate token...
    return jsonify(data='secret')

if __name__ == '__main__':
    app.run(debug=False)