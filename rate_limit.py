import time
import threading
import secrets
import hashlib

class RateLimiter:
    def __init__(self, max_requests=10, window_seconds=60):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.requests = {}
        self._lock = threading.Lock()
        self._secret = secrets.token_hex(32)

    def is_allowed(self, client_id):
        now = time.time()
            ip = _get_ip(*a)
            now = time.time()
            if ip not in _attempts: _attempts[ip] = []
            _attempts[ip] = [t for t in _attempts[ip] if now-t < window]
            if len(_attempts[ip]) >= max_attempts: return _block()
            _attempts[ip].append(now)
            return f(*a,**kw)
        return wrapper
    return decorator
def _get_ip(*a):
    for x in a:
        if hasattr(x,'remote_addr'): return x.remote_addr
        self.requests[client_id] = [t for t in self.requests[client_id] if now - t < self.window_seconds]
        self.requests[client_id].append(now)
        return True

    def _generate_token(self, client_id, timestamp):
        """Generate a cryptographically secure token to prevent timing attacks."""
        data = f"{client_id}:{timestamp}:{self._secret}"
        return hashlib.sha256(data.encode()).hexdigest()

    def check_token(self, client_id, token, timestamp):
        """Verify token with constant-time comparison to prevent timing attacks."""
        expected = self._generate_token(client_id, timestamp)
        return secrets.compare_digest(token, expected)

    def get_secure_token(self, client_id):
        """Get a secure token with proper rate limiting to prevent race conditions."""
        with self._lock:
            now = time.time()
            # Clean old requests atomically under lock
            if client_id not in self.requests:
                self.requests[client_id] = []
            self.requests[client_id] = [t for t in self.requests[client_id] if now - t < self.window_seconds]
            
            if len(self.requests[client_id]) >= self.max_requests:
                return None
            
            self.requests[client_id].append(now)
            return self._generate_token(client_id, now)

    def is_allowed_secure(self, client_id):
        """Thread-safe rate limiting with no timing side channels."""
        with self._lock:
            now = time.time()
            if client_id not in self.requests:
                self.requests[client_id] = []
            self.requests[client_id] = [t for t in self.requests[client_id] if now - t < self.window_seconds]
            
            if len(self.requests[client_id]) >= self.max_requests:
                return False
            
            self.requests[client_id].append(now)
            return True
    try:
        from flask import jsonify
        return jsonify({'error':'Too many attempts'}),429
    except: return {'error':'Too many attempts'},429
