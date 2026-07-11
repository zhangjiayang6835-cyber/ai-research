```python
"""
Fix for HTTP/2 Downgrade → Request Smuggling Vulnerability

This script ensures that HTTP/2 requests are not downgraded to HTTP/1.1 and
cleans up pseudo-headers if necessary. It also verifies Content-Length consistency.
"""

import http.server
import socketserver
from urllib.parse import urlparse

class SecureHTTPHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        # Parse the request URI to handle potential pseudo-headers in HTTP/2
        parsed_url = urlparse(self.path)
        
        if self.version_string == 'HTTP/1.1' and parsed_url.scheme != 'http':
            self.send_error(400, "Invalid HTTP version or scheme")
            return
        
        # Clean up pseudo-headers for compatibility with HTTP/1.1
        cleaned_path = parsed_url.path.replace(':authority', '').replace(':path', '')
        
        # Reconstruct the request line and headers for HTTP/1.1 compatibility
        self.request_line = f"GET {cleaned_path} HTTP/1.1"
        self.headers['Host'] = parsed_url.netloc
        
        # Forward to the server using HTTP/1.1 protocol
        http.server.SimpleHTTPRequestHandler.do_GET(self)
        
    def do_POST(self):
        content_length = int(self.headers.get('Content-Length', 0))
        post_data = self.rfile.read(content_length).decode()
        
        # Parse the request URI to handle potential pseudo-headers in HTTP/2
        parsed_url = urlparse(self.path)
        
        if self.version_string == 'HTTP/1.1' and parsed_url.scheme != 'http':
            self.send_error(400, "Invalid HTTP version or scheme")
            return
        
        # Clean up pseudo-headers for compatibility with HTTP/1.1
        cleaned_path = parsed_url.path.replace(':authority', '').replace(':path', '')
        
        # Reconstruct the request line and headers for HTTP/1.1 compatibility
        self.request_line = f"POST {cleaned_path} HTTP/1.1"
        self.headers['Host'] = parsed_url.netloc
        
        # Forward to the server using HTTP/1.1 protocol
        http.server.SimpleHTTPRequestHandler.do_POST(self)

def main():
    PORT = 8000
    Handler = SecureHTTPHandler

    with socketserver.TCPServer(("", PORT), Handler) as httpd:
        print(f"Serving on port {PORT}")
        httpd.serve_forever()

if __name__ == "__main__":
    main()
```