from flask import request, g
from functools import wraps

def jwt_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token:
            return {"error": "Token is missing"}, 401
        
        try:
            payload = decode_token(token)
            g.user_id = payload['user_id']
        except Exception as e:
            return {"error": str(e)}, 403
        
        return f(*args, **kwargs)
    return decorated_function

@jwt_required
def handle_websocket_message():
    # Handle the message here
    pass