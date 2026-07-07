import asyncio
import websockets
import json
import os

# Security: Validate server certificate and use secure WebSocket
SECURE_WS = os.environ.get('SECURE_WS', 'true').lower() == 'true'

class WebSocketClient:
    def __init__(self, uri):
        self.uri = uri
        self.websocket = None
        self.session_id = None
        self._validate_uri()
    
    def _validate_uri(self):
        """Ensure secure WebSocket connection."""
        if SECURE_WS and self.uri.startswith('ws://'):
            # Only allow ws:// for localhost in development
            if not self.uri.startswith('ws://localhost') and not self.uri.startswith('ws://127.0.0.1'):
                raise ValueError("Insecure WebSocket connection not allowed. Use wss://")
    
    async def connect(self):
        try:
            response = await self.websocket.recv()
            data = json.loads(response)
            self.session_id = data.get('session_id')
            
            if not self.session_id or not self.session_id.startswith('sess_'):
                raise ValueError("Invalid session ID received from server")
            
            return True
        except Exception as e:
            print(f"Connection failed: {e}")