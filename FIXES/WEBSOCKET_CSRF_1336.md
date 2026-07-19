# Fix: WebSocket CSRF → Cross-Origin Data Exfiltration

| Field | Value |
|-------|-------|
| Issue | [#1336](https://github.com/zhangjiayang6835-cyber/ai-research/issues/1336) |
| Bounty | $150 |
| Difficulty | Hard |
| Agent | chfr19820610-cell |
| Category | Security / WebSocket Security |

## Vulnerability

The WebSocket server at `src/websocket_server.py` validates the `Origin` header during the handshake, but does not require a CSRF token or session-bound authentication for subsequent WebSocket messages. An attacker's page can open a cross-origin WebSocket connection to the server — as long as the Origin check passes (e.g., a wildcard origin or a domain on the allow-list) or if the attacker can control a subdomain on an allowed origin — and exfiltrate sensitive data through WebSocket messages.

**Attack scenario:**

1. Victim is authenticated to `app.example.com` (an allowed origin)
2. Attacker's page on `evil.com` opens a WebSocket to `ws://app.example.com:8765`
3. Origin check passes (if origin validation is weak or attacker controls an allowed subdomain)
4. Attacker sends `{"action": "get_data", "type": "sensitive"}`  
5. Server processes the request using the attacker's WebSocket, returning data

## Root Cause

The server only validates the `Origin` header at connection time. It does NOT:
- Verify that the WebSocket connection carries a session-bound CSRF token
- Re-authenticate WebSocket messages against the user's HTTP session
- Use origin validation that checks against a strict allow-list

## Fix Implementation

### 1. Strict Origin Validation

Replace substring matching with exact domain allow-list matching:

```python
ALLOWED_ORIGINS = {'http://localhost:3000', 'https://app.example.com'}
```

### 2. CSRF Token in WebSocket Upgrade

Require a proof-of-possession CSRF token during the WebSocket handshake. Only WebSocket upgrade requests that include a valid CSRF token (matching the user's HTTP session) are accepted:

```python
async def handle_client(websocket, path):
    # Extract CSRF token from subprotocol or query string
    csrf_token = websocket.request_headers.get('Sec-WebSocket-Protocol', '')
    if not _validate_ws_csrf_token(csrf_token):
        await websocket.close(code=1008, reason='CSRF validation failed')
        return
    
    # Validate origin
    if not validate_origin(websocket):
        await websocket.close(code=1008, reason='Invalid origin')
        return
```

### 3. Session-Bound Message Authentication

Bind every WebSocket message to the user's HTTP session. Each message payload must include a session-bound token that is verified before processing:

```python
class AuthenticatedWebSocket:
    def __init__(self, websocket, session_id: str):
        self.ws = websocket
        self.session_id = session_id
    
    async def verify_message(self, data: dict) -> bool:
        msg_token = data.get('_token', '')
        expected = hmac.new(
            SESSION_SECRET.encode(),
            f"{self.session_id}:{data.get('action', '')}".encode(),
            hashlib.sha256
        ).hexdigest()[:16]
        return hmac.compare_digest(msg_token, expected)
```

### 4. Data Access Control

Sensitive data retrieval requires explicit permission check per message, not just at connection time.

## Testing

See `tests/test_websocket_csrf_1336.py` for coverage including:

- Origin validation rejects unauthorized origins
- WebSocket upgrade without CSRF token is rejected
- Valid CSRF token in WebSocket upgrade succeeds
- Message without session token is rejected
- Message with tampered token is rejected
- Attacker cannot read sensitive data via cross-origin WebSocket
- Legacy behavior: same-origin WebSocket still works normally
