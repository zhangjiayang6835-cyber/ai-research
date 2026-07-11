```python
import socketio
from flask import Flask, request, abort
from werkzeug.security import generate_password_hash, check_password_hash
import secrets

app = Flask(__name__)
sio = socketio.Server(async_mode='threading', cors_allowed_origins=[])

# Mock data store for users and tokens
users = {
    'user1': generate_password_hash('password1'),
    'user2': generate_password_hash('password2')
}
tokens = {}

@app.route('/login', methods=['POST'])
def login():
    username = request.json.get('username')
    password = request.json.get('password')
    if not username or not password:
        abort(400)
    
    hashed_password = users.get(username)
    if not check_password_hash(hashed_password, password):
        abort(401)

    token = secrets.token_urlsafe(32)
    tokens[token] = username
    return {'token': token}

@sio.on('connect')
def connect(sid, environ):
    origin = environ['HTTP_ORIGIN']
    if origin not in ['http://trusted.com', 'https://trusted.com']:  # Add more trusted origins as needed
        abort(403)
    
    challenge_token = secrets.token_urlsafe(16)
    tokens[sid] = {'challenge': challenge_token, 'user': None}
    sio.emit('csrf_challenge', challenge_token)

@sio.on('csrf_response')
def csrf_response(sid, data):
    token = tokens.get(sid)
    if not token or 'challenge' not in token:
        abort(403)
    
    expected_challenge = token['challenge']
    if expected_challenge != data:
        abort(403)
    
    username = users.get(data)  # Simulate fetching user from the database
    if username is None:
        abort(401)
    
    token = secrets.token_urlsafe(32)
    tokens[sid]['user'] = username
    sio.emit('csrf_response', {'token': token})

@sio.on('disconnect')
def disconnect(sid):
    if sid in tokens:
        del tokens[sid]

if __name__ == '__main__':
    app.run()
```

This code snippet provides a basic implementation for addressing the WebSocket CSRF vulnerability. It includes origin header validation and a challenge-response mechanism to ensure that only trusted origins can establish connections.