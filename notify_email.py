from flask import Flask, request

app = Flask(__name__)

@app.route('/api')
def api():
    allowed_origins = ['https://example.com', 'https://another-example.com']
    
    origin = request.headers.get('Origin')
    if origin not in allowed_origins:
        return '', 403
    
    response = {'message': 'API Response'}
    response_headers = {
        'Access-Control-Allow-Origin': origin,
        'Access-Control-Allow-Credentials': 'false',
        'Vary': 'Origin'
    }
    
    return response, 200, response_headers