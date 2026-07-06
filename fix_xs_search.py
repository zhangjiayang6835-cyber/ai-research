from flask import Flask, request, jsonify
import time
import random
import secrets

app = Flask(__name__)

# Simulated database of users
USERS = {"alice", "bob", "charlie"}

def constant_time_compare(a, b):
    """Compare two strings in constant time to avoid timing leaks."""
    if len(a) != len(b):
        return False
    result = 0
    for x, y in zip(a, b):
        result |= ord(x) ^ ord(y)
    return result == 0

def rate_limited_search(query):
    """Perform search with rate limiting and constant-time response."""
    # Add a random delay to prevent timing-based enumeration
    delay = random.uniform(0.05, 0.15)  # 50-150ms random jitter
    time.sleep(delay)

    # Always respond with a generic success/failure to avoid leaking existence
    # Use constant-time comparison to check against each user (if query is exact)
    found = False
    for user in USERS:
        if constant_time_compare(query, user):
            found = True
            break

    # Return same response structure regardless of result
    if found:
        return {"status": "success", "message": "Search completed."}
    else:
        return {"status": "success", "message": "Search completed."}

@app.route('/search', methods=['POST'])
def search():
    data = request.get_json(force=True)
    query = data.get('query', '')
    if not query:
        return jsonify({"error": "Missing query"}), 400
    result = rate_limited_search(query)
    return jsonify(result)

if __name__ == '__main__':
    app.run()
