from flask import Flask, request, abort

app = Flask(__name__)

@app.before_request
def prevent_request_smuggling():
    # Check for conflicting Content-Length and Transfer-Encoding headers
    content_length = request.headers.get('Content-Length')
    transfer_encoding = request.headers.get('Transfer-Encoding')

    if transfer_encoding and 'chunked' in transfer_encoding.lower():
        if content_length:
            # Reject request with both Content-Length and chunked Transfer-Encoding
            abort(400, 'Request smuggling detected: conflicting Content-Length and Transfer-Encoding')
        # Ensure proper chunked encoding handling (already handled by Flask/Werkzeug)

    # Optionally reject multiple Content-Length headers
    cl_headers = request.headers.getlist('Content-Length')
    if len(cl_headers) > 1:
        abort(400, 'Request smuggling detected: multiple Content-Length headers')

    # Ensure no Transfer-Encoding header with unexpected values
    if transfer_encoding:
        if ',' in transfer_encoding:
            # Multiple Transfer-Encoding values may indicate smuggling
            abort(400, 'Request smuggling detected: multiple Transfer-Encoding values')
        # Only 'chunked' and 'identity' are standard; block others?
        # This is a strict policy
        valid_te = ['chunked', 'identity']
        if transfer_encoding.lower() not in valid_te:
            abort(400, 'Request smuggling detected: invalid Transfer-Encoding')

@app.route('/')
def index():
    return 'Hello, World!'

if __name__ == '__main__':
    app.run()
