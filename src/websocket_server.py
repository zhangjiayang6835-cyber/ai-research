import asyncio
import websockets
import json
import os
import secrets
import hashlib
import hmac
from datetime import datetime

# Security configuration
ALLOWED_ORIGINS = os.environ.get('ALLOWED_ORIGINS', 'http://localhost:3000,https://app.example.com').split(',')
SESSION_SECRET = os.environ.get('SESSION_SECRET', secrets.token_hex(32))

class SessionManager:
    def __init__(self):
        self.sessions = {}
        self._secret = secrets.token_bytes(32)
    
    def create_session(self, client_info):
        # Use cryptographically secure random token instead of predictable counter
        random_token = secrets.token_urlsafe(32)
        timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
        # HMAC-based session ID prevents prediction
        session_data = f"{client_info['ip']}:{timestamp}:{random_token}"
        session_hash = hmac.new(self._secret, session_data.encode(), hashlib.sha256).hexdigest()[:16]
        session_id = f"sess_{session_hash}_{timestamp}_{random_token[:8]}"
        self.sessions[session_id] = {
            'created_at': datetime.now(),
            'client_info': client_info,
    def get_session(self, session_id):
        return self.sessions.get(session_id)
    
    def validate_session(self, session_id, client_ip):
        session = self.sessions.get(session_id)
        if not session:
            return False
        return session['client_info'].get('ip') == client_ip
    
    def update_session(self, session_id, data):
        if session_id in self.sessions:
            self.sessions[session_id]['data'].update(data)

session_manager = SessionManager()

def validate_origin(websocket):
    """Validate the Origin header to prevent cross-origin WebSocket hijacking."""
    origin = websocket.request_headers.get('Origin')
    if not origin:
        # If no origin is provided, check Referer as fallback
        origin = websocket.request_headers.get('Referer', '')
    
    if not origin:
        return False
    
    # Normalize origin for comparison
    origin = origin.rstrip('/')
    
    for allowed in ALLOWED_ORIGINS:
        allowed = allowed.strip().rstrip('/')
        if origin == allowed:
            return True
    
    return False

def get_client_ip(websocket):
    """Extract client IP from websocket connection."""
    # Try to get real IP from headers first (for proxies)
    forwarded = websocket.request_headers.get('X-Forwarded-For')
    if forwarded:
        return forwarded.split(',')[0].strip()
    return websocket.remote_address[0] if websocket.remote_address else 'unknown'

async def handle_client(websocket, path):
    # Validate origin before accepting connection
    if not validate_origin(websocket):
        await websocket.close(code=1008, reason='Invalid origin')
        return
    
    client_ip = get_client_ip(websocket)
    session = session_manager.create_session({'ip': client_ip})
    
    try:
                data = json.loads(message)
                action = data.get('action')
                
                # Validate session ownership on every message
                if not session_manager.validate_session(session['id'], client_ip):
                    await websocket.send(json.dumps({'error': 'Session validation failed'}))
                    continue
                
                if action == 'ping':
                    await websocket.send(json.dumps({'type': 'pong'}))
                elif action == 'get_data':
        del session_manager.sessions[session['id']]

async def main():
    server = await websockets.serve(handle_client, '0.0.0.0', 8765, origins=None)
    await server.wait_closed()

if __name__ == '__main__':