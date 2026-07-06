from flask_socketio import SocketIO, emit, disconnect
from flask import request, Flask

app = Flask(__name__)
socketio = SocketIO(app, cors_allowed_origins=[])

ALLOWED_ORIGINS = ['https://yourdomain.com', 'http://localhost:5000']

@socketio.on('connect')
def handle_connect():
    origin = request.headers.get('Origin')
    if origin and origin not in ALLOWED_ORIGINS:
        disconnect()
        return False
    print('Client connected')

@socketio.on('message')
def handle_message(msg):
    emit('response', {'data': msg})

if __name__ == '__main__':
    socketio.run(app, debug=True)
