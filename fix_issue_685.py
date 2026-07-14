"""Fix for Issue #685: WebSocket Hijacking via Missing Cookie Validation"""
import re
import json
import hmac
import hashlib
import secrets
import time

SECURITY_FIX = True

class WebSocketSecurity:
    """WebSocket security guard with per-message token validation."""
    
    def __init__(self):
        self.active_sessions = {}
    
    def create_session(self, user_id, token=None):
        """Create a WebSocket session with bound token."""
        if not token:
            token = secrets.token_hex(32)
        session_id = secrets.token_hex(16)
        self.active_sessions[session_id] = {
            "user_id": user_id,
            "token": token,
            "created_at": time.time(),
            "messages_validated": 0
        }
        return {"session_id": session_id, "token": token}
    
    def validate_message(self, session_id, token, message_data=""):
        """Validate each WebSocket message with the session token."""
        if session_id not in self.active_sessions:
            return False, "Session not found"
        session = self.active_sessions[session_id]
        if not hmac.compare_digest(session["token"], token):
            return False, "Invalid token"
        session["messages_validated"] += 1
        return True, "Message validated"
    
    def close_session(self, session_id):
        """Close and remove a WebSocket session."""
        if session_id in self.active_sessions:
            del self.active_sessions[session_id]
            return True
        return False

def apply_security_patch(input_data):
    """Apply security fix: WebSocket per-message token validation."""
    if not isinstance(input_data, dict):
        return {"status": "error", "data": "Invalid input"}
    
    guard = WebSocketSecurity()
    action = input_data.get("action", "")
    
    if action == "connect":
        user_id = input_data.get("user_id", "anonymous")
        existing_token = input_data.get("token", None)
        session = guard.create_session(user_id, existing_token)
        return {
            "status": "patched",
            "data": {
                "session_id": session["session_id"],
                "token": session["token"],
                "message": "WebSocket connected with per-message token validation"
            }
        }
    
    elif action == "message":
        session_id = input_data.get("session_id", "")
        token = input_data.get("token", "")
        msg = input_data.get("message", "")
        valid, msg_text = guard.validate_message(session_id, token, msg)
        if not valid:
            return {"status": "rejected", "data": msg_text}
        return {"status": "patched", "data": f"Message validated: {msg[:50]}"}
    
    elif action == "close":
        session_id = input_data.get("session_id", "")
        guard.close_session(session_id)
        return {"status": "patched", "data": "Session closed"}
    
    return {"status": "error", "data": "Unknown action"}

if __name__ == "__main__":
    # Test 1: Connect creates session with token
    result = apply_security_patch({"action": "connect", "user_id": "user-123"})
    assert result["status"] == "patched", f"Connection failed: {result}"
    session_id = result["data"]["session_id"]
    token = result["data"]["token"]
    print(f"✓ WebSocket connected: session={session_id[:8]}...")
    
    # Test 2: Valid message passes
    result = apply_security_patch({"action": "message", "session_id": session_id, "token": token, "message": "ping"})
    assert result["status"] == "patched", f"Valid message rejected: {result}"
    print("✓ Valid message accepted")
    
    # Test 3: Invalid token rejected
    result = apply_security_patch({"action": "message", "session_id": session_id, "token": "fake-token", "message": "hack"})
    assert result["status"] == "rejected", f"Invalid token not rejected: {result}"
    print("✓ Invalid token rejected")
    
    # Test 4: Unknown session rejected
    result = apply_security_patch({"action": "message", "session_id": "nonexistent", "token": token, "message": "test"})
    assert result["status"] == "rejected", f"Unknown session not rejected: {result}"
    print("✓ Unknown session rejected")
    
    # Test 5: Close session
    result = apply_security_patch({"action": "close", "session_id": session_id})
    assert result["status"] == "patched", f"Close failed: {result}"
    print("✓ Session closed")
    
    print("\n✅ All tests passed for #685: WebSocket Hijacking Fix")