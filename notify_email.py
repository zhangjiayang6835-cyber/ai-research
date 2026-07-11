from flask import Flask, request, make_response

app = Flask(__name__)

@app.route('/')
def index():
    response = make_response("Hello, World!")
    # Normalize and include all relevant headers in the cache key
    vary_headers = ['Authorization', 'Cookie', 'X-Forwarded-For', 'X-Forwarded-Proto', 'X-Forwarded-Port', 'X-Forwarded-Host']
    response.headers['Vary'] = ', '.join(vary_headers)
    
    # Example of setting a header that should not be cached
    response.headers.pop('X-Forwarded-Host', None)
    
    return response

if __name__ == '__main__':
    app.run()