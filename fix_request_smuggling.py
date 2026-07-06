import re
from wsgiref import util

class RequestSmugglingFixMiddleware:
    """
    WSGI middleware to mitigate HTTP request smuggling vulnerabilities.
    Rejects requests with ambiguous or malformed Transfer-Encoding / Content-Length headers.
    """
    def __init__(self, app):
        self.app = app

    def __call__(self, environ, start_response):
        # Validate headers to prevent desync attacks
        if not self._validate_headers(environ):
            start_response('400 Bad Request', [('Content-Type', 'text/plain')])
            return [b'Request rejected due to ambiguous headers']

        return self.app(environ, start_response)

    def _validate_headers(self, environ):
        # Normalize header names to lowercase for comparison
        headers = {}
        for key, value in environ.items():
            if key.startswith('HTTP_'):
                header_name = key[5:].replace('_', '-').lower()
                headers[header_name] = value

        te = headers.get('transfer-encoding', '').strip()
        cl = headers.get('content-length', '').strip()

        # Reject if both Transfer-Encoding and Content-Length are present and non-empty
        if te and cl:
            return False

        # If Transfer-Encoding is present, it must be properly formatted
        if te:
            # Transfer-Encoding can be a list of codings; we only accept 'chunked' alone
            # Remove whitespace and split by commas to handle multiple codings
            te_values = [v.strip().lower() for v in te.split(',')]
            # According to RFC 7230, multiple encodings are allowed but we restrict to chunked
            if te_values != ['chunked']:
                return False

        # If Content-Length is present, it must be a single positive integer without leading zeros
        if cl:
            if not re.match(r'^[1-9]\d*$', cl):
                # Zero is allowed? Typically not for request bodies in smuggling context
                # Reject zero as it may indicate smuggling
                if cl != '0':
                    return False
                # Zero is allowed but we should ensure no body is sent (handled by WSGI server)

        # Additional check: ensure request integrity; this is a basic filter
        return True

def make_wsgi_app(app):
    return RequestSmugglingFixMiddleware(app)
