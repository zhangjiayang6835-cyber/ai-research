from flask import Flask, request
from wsgiref.util import setup_testing_defaults
from wsgiref.simple_server import make_server

def clean_pseudo_headers(environ):
    # Remove HTTP/2 specific pseudo-headers
    if 'HTTP_2__AUTHORITY' in environ:
        del environ['HTTP_2__AUTHORITY']
    if 'HTTP_2__PATH' in environ:
        del environ['HTTP_2__PATH']
    return environ

class CleanHeadersMiddleware:
    def __init__(self, app):
        self.app = app

    def __call__(self, environ, start_response):
        # Clean up pseudo-headers
        clean_environ = clean_pseudo_headers(environ)
        return self.app(clean_environ, start_response)

def verify_content_length(environ):
    content_length = environ.get('CONTENT_LENGTH')
    if content_length:
        try:
            content_length = int(content_length)
            if content_length > 0:
                input_stream = environ['wsgi.input']
                actual_length = len(input_stream.read())
                if actual_length!= content_length:
                    raise ValueError("Content-Length does not match the actual content length")
                # Reset the stream after reading
                input_stream.seek(0)
        except ValueError as e:
            return str(e)
    return None

class VerifyContentLengthMiddleware:
    def __init__(self, app):
        self.app = app

    def __call__(self, environ, start_response):
        error = verify_content_length(environ)
        if error:
            start_response('400 Bad Request', [('Content-Type', 'text/plain')])
            return [error.encode('utf-8')]
        return self.app(environ, start_response)

class CombinedMiddleware:
    def __init__(self, app):
        self.app = app

    def __call__(self, environ, start_response):
        # Clean up pseudo-headers
        clean_environ = clean_pseudo_headers(environ)
        
        # Verify Content-Length
        error = verify_content_length(clean_environ)
        if error:
            start_response('400 Bad Request', [('Content-Type', 'text/plain')])
            return [error.encode('utf-8')]
        
        return self.app(clean_environ, start_response)

app = Flask(__name__)

@app.route('/')
def index():
    return "Hello, World!"

# Wrap the Flask app with the combined middleware
app.wsgi_app = CombinedMiddleware(app.wsgi_app)

if __name__ == '__main__':
    from werkzeug.serving import run_simple
    run_simple('localhost', 8080, app)