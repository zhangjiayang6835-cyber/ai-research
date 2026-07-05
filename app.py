from flask import Flask, request, jsonify
from flask_cors import CORS

app = Flask(__name__)

# Whitelist of allowed origins (configure per environment)
ALLOWED_ORIGINS = {
    'https://trusted-frontend.com',
    'http://localhost:3000',
}

@app.after_request
def add_cors_headers(response):
    origin = request.headers.get('Origin')
    if origin in ALLOWED_ORIGINS:
        response.headers['Access-Control-Allow-Origin'] = origin
        response.headers['Access-Control-Allow-Credentials'] = 'true'
    else:
        # Optionally, set a default safe origin or omit the header
        # We recommend setting a default safe origin if credentials are needed
        # For public API without credentials, use '*'
        response.headers['Access-Control-Allow-Origin'] = 'https://trusted-frontend.com'
    response.headers['Access-Control-Allow-Methods'] = 'GET, POST, PUT, DELETE, OPTIONS'
    response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization'
    return response

@app.route('/api/data')
def get_data():
    # Simulated sensitive data
    return jsonify({'secret': 'sensitive-data'})

if __name__ == '__main__':
    app.run(debug=True)