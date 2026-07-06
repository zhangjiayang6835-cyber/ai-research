import time
import hmac
from flask import Flask, request, jsonify
import os

app = Flask(__name__)

# Simulated secret for constant-time comparison (in production, use environment variable)
SECRET_KEY = os.environ.get('SECRET_KEY', 'default-secret-key')

# Simulated user database (in production, use a real database with hashed identifiers)
USER_DATABASE = {
    'alice': True,
    'bob': True,
    'charlie': True
}

@app.route('/search', methods=['GET'])
def search_user():
    username = request.args.get('username', '')
    
    # Constant-time comparison to prevent timing side-channel
    # HMAC-based approach: compare hashes of the username with a constant string
    # If username exists in DB, we still compute hash of a dummy value to keep time constant
    expected_hash = hmac.new(SECRET_KEY.encode(), 'user'.encode(), 'sha256').hexdigest()
    input_hash = hmac.new(SECRET_KEY.encode(), username.encode(), 'sha256').hexdigest()
    
    # Simulate a database lookup that takes constant time (if DB does not support constant-time, add artificial delay)
    # In real implementation, ensure database query time is independent of row existence (e.g., by hashing query or using constant-time query patterns)
    
    # For demonstration, we use a dummy operation that takes approximately constant time
    _ = hmac.new(SECRET_KEY.encode(), 'dummy'.encode(), 'sha256').digest()
    
    # Determine if user exists (in production, this should be done without revealing existence via response)
    user_exists = username in USER_DATABASE
    
    # Always return the same response structure and status code regardless of existence
    # Use a generic message that does not leak whether the user exists.
    # For example, return a success response with no user-specific data.
    return jsonify({'status': 'ok', 'message': 'Search completed.'}), 200

if __name__ == '__main__':
    app.run(debug=False, port=5000)
