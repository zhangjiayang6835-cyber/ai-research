from flask import Flask, request, make_response
from flask import current_app

app = Flask(__name__)

@app.after_request
def add_csp_header(response):
    csp_policy = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' 'unsafe-eval'; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; "
        "font-src 'self'; "
        "connect-src 'self'; "
        "frame-ancestors 'none'; "
        "form-action 'self'; "
        "base-uri 'self'"
    )
    response.headers['Content-Security-Policy'] = csp_policy
    return response

if __name__ == '__main__':
    app.run()
