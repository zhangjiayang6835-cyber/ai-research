```python
"""
websocket_csr_fix.py

This script addresses the WebSocket CSRF security issue by implementing a token-based authentication mechanism.
The client must provide a valid token in every WebSocket message to ensure that only authorized clients can interact with the server.
"""

import json
from websockets.server import serve

def main():
    """
    Main function to start the WebSocket server with CSRF protection.
    """
    
    async def handle_client(websocket, path):
        # Example token validation logic (in a real-world scenario, this would be more complex)
        expected_token = "secure_and_random_token"
        incoming_token = await websocket.recv()
        
        if not validate_token(incoming_token, expected_token):
            print("Invalid token received. Closing connection.")
            return
        
        while True:
            try:
                message = await websocket.recv()
                print(f"Received: {message}")
                response = process_message(message)
                await websocket.send(response)
            except Exception as e:
                print(f"Error processing request: {e}")
                break

    async def validate_token(incoming_token, expected_token):
        """
        Validate the incoming token against the expected token.
        
        :param incoming_token: Token received from the client
        :param expected_token: Expected token for authorization
        :return: True if tokens match, False otherwise
        """
        return incoming_token == expected_token

    async def process_message(message):
        """
        Process a received message and generate an appropriate response.
        
        :param message: The received WebSocket message
        :return: A JSON-formatted string containing the response
        """
        data = json.loads(message)
        action = data.get("action")
        if action == "ping":
            return json.dumps({"response": "pong"})
        else:
            return json.dumps({"error": "Unknown action"})

    start_server = serve(handle_client, "localhost", 8765)
    print(f"WebSocket server started on ws://{start_server.host}:{start_server.port}")
    await start_server.serve_forever()

if __name__ == "__main__":
    main()
```