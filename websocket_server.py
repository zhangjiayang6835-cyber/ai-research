import asyncio
import websockets
import jwt
from datetime import datetime, timedelta

# Secret key for JWT (keep this secure in a real application)
SECRET_KEY = 'your_secret_key'

# Simulated user session storage (in a real application, use a database)
user_sessions = {}

def create_jwt_token(user_id):
    payload = {
        'user_id': user_id,
        'exp': datetime.utcnow() + timedelta(hours=1)
    }
    return jwt.encode(payload, SECRET_KEY, algorithm='HS256')

def validate_jwt_token(token):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
        return payload['user_id']
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None

async def handler(websocket, path):
    # Verify Bearer token upon WebSocket connection
    try:
        auth_header = websocket.request_headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            await websocket.close(400, "Missing or invalid Bearer token")
            return

        token = auth_header.split(' ')[1]
        user_id = validate_jwt_token(token)

        if user_id is None:
            await websocket.close(401, "Invalid or expired token")
            return

        # Bind the token to a user session
        user_sessions[websocket] = user_id

        async for message in websocket:
            # Validate the token for each WebSocket message
            if websocket not in user_sessions:
                await websocket.close(401, "Session not found")
                break

            # Process the message
            print(f"Received message from user {user_sessions[websocket]}: {message}")
            await websocket.send(f"Echo: {message}")

    finally:
        # Clean up the session when the connection is closed
        if websocket in user_sessions:
            del user_sessions[websocket]

start_server = websockets.serve(handler, "localhost", 8765)

asyncio.get_event_loop().run_until_complete(start_server)
asyncio.get_event_loop().run_forever()