import asyncio
import websockets
import json
from urllib.parse import urlparse

# Simulated database of valid tokens
valid_tokens = {
    "token1": "user1",
    "token2": "user2"
}

# Allowed origins
allowed_origins = [
    "https://example.com",
    "https://secure.example.com"
]

async def authenticate_token(token):
    """Check if the provided token is valid."""
    return token in valid_tokens

async def validate_origin(origin):
    """Check if the origin is allowed."""
    parsed_origin = urlparse(origin)
    return any(parsed_origin.netloc == allowed_origin for allowed_origin in allowed_origins)

async def handler(websocket, path):
    # Get the origin header from the incoming request
    origin = websocket.request_headers.get('Origin', '')

    # Validate the origin
    if not await validate_origin(origin):
        await websocket.close(403, "Forbidden: Invalid Origin")
        return

    # Get the token from the query parameters
    query_params = dict((param.split('=') for param in path.split('?')[1].split('&')))
    token = query_params.get('token', '')

    # Authenticate the token
    if not await authenticate_token(token):
        await websocket.close(401, "Unauthorized: Invalid Token")
        return

    try:
        async for message in websocket:
            data = json.loads(message)
            print(f"Received message: {data}")
            # Process the message
            response = {"status": "success", "message": "Message received"}
            await websocket.send(json.dumps(response))
    except websockets.ConnectionClosed:
        pass

start_server = websockets.serve(handler, "localhost", 8765)

asyncio.get_event_loop().run_until_complete(start_server)
asyncio.get_event_loop().run_forever()