 ```diff
--- a/src/http_server.py
+++ b/src/http_server.py
@@ -0,0 +1,247 @@
+"""
+Secure HTTP Server with HTTP Request Smuggling and Cache Poisoning protections.
+
+This module implements a hardened HTTP/1.1 server that mitigates:
+- HTTP Request Smuggling (HRS) via strict header validation
+- Cache Poisoning via proper cache-control and validation
+"""
+
+import re
+import socket
+import threading
+import logging
+from urllib.parse import unquote
+
+# Configure logging
+logging.basicConfig(level=logging.INFO)
+logger = logging.getLogger(__name__)
+
+
+class HTTPError(Exception):
+    """Custom HTTP error with status code and message."""
+    def __init__(self, status_code, message):
+        self.status_code = status_code
+        self.message = message
+        super().__init__(message)
+
+
+class SecureHTTPServer:
+    """
+    Secure HTTP/1.1 server with protections against:
+    - HTTP Request Smuggling (CL.TE, TE.CL, TE.TE variants)
+    - Cache Poisoning attacks
+    """
+    
+    # Security constants
+    MAX_HEADER_SIZE = 8192  # 8KB max header size
+    MAX_BODY_SIZE = 1024 * 1024  # 1MB max body
+    MAX_HEADERS_COUNT = 100
+    MAX_URI_LENGTH = 2048
+    
+    # Forbidden headers that could be used for smuggling
+    FORBIDDEN_HEADERS = {
+        'transfer-encoding',
+        'content-length',
+        'connection',
+    }
+    
+    # Headers that should not be trusted from client for caching
+    UNTRUSTED_CACHE_HEADERS = {
+        'x-cache',
+        'x-cache-lookup',
+        'x-cacheable',
+        'cf-cache-status',
+        'x-varnish',
+        'x-squid',
+    }
+    
+    def __init__(self, host='0.0.0.0', port=8080):
+        self.host = host
+        self.port = port
+        self.server_socket = None
+        self.running = False
+        
+    def start(self):
+        """Start the secure HTTP server."""
+        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
+        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
+        self.server_socket.bind((self.host, self.port))
+        self.server_socket.listen(5)
+        self.running = True
+        
+        logger.info(f"Secure HTTP server listening on {self.host}:{self.port}")
+        
+        while self.running:
+            try:
+                client_socket, address = self.server_socket.accept()
+                client_thread = threading.Thread(
+                    target=self._handle_client,
+                    args=(client_socket, address),
+                    daemon=True
+                )
+                client_thread.start()
+            except Exception as e:
+                logger.error(f"Error accepting connection: {e}")
+                
+    def stop(self):
+        """Stop the server."""
+        self.running = False
+        if self.server_socket:
+            self.server_socket.close()
+            
+    def _handle_client(self, client_socket, address):
+        """Handle a single client connection."""
+        try:
+            # Set timeout to prevent slowloris attacks
+            client_socket.settimeout(30)
+            
+            # Read request
+            request_data = self._read_request(client_socket)
+            if not request_data:
+                return
+                
+            # Parse and validate request
+            try:
+                response = self._process_request(request_data)
+            except HTTPError as e:
+                response = self._build_error_response(e.status_code, e.message)
+                
+            # Send response
+            client_socket.sendryp(response)
+            
+        except Exception as e:
+            logger.error(f"Error handling client {address}: {e}")
+        finally:
+            client_socket.close()
+            
+    def _read_request(self, client_socket):
+        """Read and validate the HTTP request from client."""
+        try:
+            data = b''
+            while True:
+                chunk = client_socket.recv(4096)
+                if not chunk:
+                    break
+                data += chunk
+                
+                # Check max header size
+                if len(data) > self.MAX_HEADER_SIZE + self.MAX_BODY_SIZE:
+                    raise HTTPError(413, "Request Entity Too Large")
+                    
+                # Check for end of headers
+                if b'\r\n\r\n' in data:
+                    break
+                    
+            return data
+        except socket.timeout:
+            raise HTTPError(408, "Request Timeout")
+        except Exception as e:
+            logger.error(f"Error reading request: {e}")
+            return None
+            
+    def _parse_request_line(self, line):
+        """Parse and validate the request line."""
+        parts = line.split(' ')
+        if len(parts) != 3:
+            raise HTTPError(400, "Bad Request: Invalid request line")
+            
+        method, uri, version = parts
+        
+        # Validate method
+        valid_methods = {'GET', 'POST', 'PUT', 'DELETE', 'HEAD', 'OPTIONS', 'PATCH'}
+        if method not in valid_methods:
+            raise HTTPError(405, "Method Not Allowed")
+            
+        # Validate URI length
+        if len(uri) > self.MAX_URI_LENGTH:
+            raise HTTPError(414, "URI Too Long")
+            
+        # Validate URI characters
+        if not self._is_valid_uri(uri):
+            raise HTTPError(400, "Bad Request: Invalid URI")
+            
+        # Validate HTTP version
+        if version not in ('HTTP/1.0', 'HTTP/1.1'):
+            raise HTTPError(505, "HTTP Version Not Supported")
+            
+        return method, uri, version
+        
+    def _is_valid_uri(self, uri):
+        """Check if URI contains only valid characters."""
+        # Allow only safe characters
+        allowed = set(
+            "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
+            "abcdefghijklmnopqrstuvwxyz"
+            "0123456789"
+            "-._~:/?#[]@!$&'()*+,;=%"
+        )
+        return all(c in allowed for c in uri)
+        
+    def _parse_headers(self, header_lines):
+        """Parse and validate headers."""
+        headers = {}
+        
+        for line in header_lines:
+            if ':' not in line:
+                raise HTTPError(400, "Bad Request: Invalid header")
+                
+            name, value = line.split(':', 1)
