
"""
Rate limiting middleware for login endpoints.
"""
import time
from functools import wraps
_attempts = {}
def rate_limit(max_attempts=5, window=60):
    def decorator(f):
        @wraps(f)
        def wrapper(*a,**kw):
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
        if hasattr(x,'META'): return x.META.get('REMOTE_ADDR','0.0.0.0')
    return '0.0.0.0'
def _block():
    try:
        from flask import jsonify
        return jsonify({'error':'Too many attempts'}),429
    except: return {'error':'Too many attempts'},429
