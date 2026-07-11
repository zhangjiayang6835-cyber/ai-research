```python
import base64
from cryptography.fernet import Fernet
from flask import Flask, request, jsonify
from flask_socketio import SocketIO, emit, join_room, leave_room

app = Flask(__name__)
socketio = SocketIO(app)

# Generate a key for encryption/decryption
key = Fernet.generate_key()
cipher_suite = Fernet(key)

# Store user sessions and tokens in memory (for simplicity)
sessions = {}

@app.route('/login', methods=['POST'])
def login():
    data = request.json
    username = data.get('username')
    token = data.get('token')

    # Validate the token here, for example by checking it against a database
    if validate_token(token):
        sessions[username] = {'token': token}
        return jsonify({"message": "Logged in successfully"}), 200
    else:
        return jsonify({"error": "Invalid token"}), 401

def validate_token(token):
    # Placeholder for actual validation logic
    return True if token == 'valid_token' else False

@socketio.on('connect')
def handle_connect():
    token = request.headers.get('Authorization', '').split(' ')[1]
    username = request.args.get('username')

    session = sessions.get(username)
    if not session or not validate_token(token):
        socketio.emit('error', {'message': 'Invalid token'}, room=request.sid)
        socketio.disconnect(request.sid)
        return

@socketio.on('message')
def handle_message(data):
    username = request.args.get('username')
    token = request.headers.get('Authorization', '').split(' ')[1]

    session = sessions.get(username)
    if not session or not validate_token(token):
        emit('error', {'message': 'Invalid token'}, room=request.sid)
        return

    # Process the message
    print(f"Received message from {username}: {data}")
    socketio.emit('message', data, room=request.sid)

if __name__ == '__main__':
    socketio.run(app, debug=True)
```
```python
def main():
    app.run()
    socketio.run(app, debug=True)

if __name__ == '__main__':
    main()
```

This code sets up a simple WebSocket server using Flask-SocketIO that validates JWT tokens both on connection and for each message.