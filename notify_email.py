from flask import request, abort

def handle_websocket_origin():
    origin = request.headers.get('Origin')
    if not origin or origin != 'https://valid-origin.com':
        abort(403)
    
    # CSRF Token Handshake
    challenge_token = request.cookies.get('csrf_token')
    response_token = request.args.get('token')
    if not challenge_token or not response_token or challenge_token != response_token:
        abort(403)
    
    # Proceed with WebSocket connection
    # ...