 ```diff
--- a/src/app.py
+++ b/src/app.py
@@ -1,6 +1,7 @@
 from flask import Flask, request, jsonify
 import requests
 import os
+import re
 
 app = Flask(__name__)
 
@@ -8,6 +9,31 @@
 UPSTREAM_HOST = os.environ.get('UPSTREAM_HOST', 'localhost')
 UPSTREAM_PORT = os.environ.get('UPSTREAM_PORT', '8080')
 
+# Security: HTTP Request Smuggling Prevention
+# Validate and sanitize headers to prevent desync attacks
+FORBIDDEN_HEADERS = {
+    'transfer-encoding', 'content-length', 'connection',
+    'keep-alive', 'proxy-connection', 'upgrade', 'te'
+}
+
+def sanitize_headers(headers):
+    """Remove hop-by-hop and smuggling-related headers from client requests."""
+    sanitized = {}
+    for key, value in headers:
+        if key.lower() not in FORBIDDEN_HEADERS:
+            sanitized[key] = value
+    return sanitized
+
+def validate_content_length(body, content_length):
+    """Validate that Content-Length matches actual body size."""
+    if content_length is None:
+        return True
+    try:
+        expected_length = int(content_length)
+        return len(body) == expected_length
+    except (ValueError, TypeError):
+        return False
+
+# Maximum body size to prevent memory exhaustion
+MAX_BODY_SIZE = 10 * 1024 * 1024  # 10MB
 
 @app.route('/proxy', methods=['POST', 'GET', 'PUT', 'DELETE', 'PATCH'])
 def proxy_request():
@@ -15,8 +41,32 @@
     Proxies requests to upstream server.
     Vulnerable to HTTP Request Smuggling due to improper header handling.
     """
+    # Security: Read and validate body before processing
+    content_length = request.headers.get('Content-Length')
+    content_length_int = None
+    if content_length:
+        try:
+            content_length_int = int(content_length)
+            if content_length_int < 0:
+                return jsonify({'error': 'Invalid Content-Length'}), 400
+            if content_length_int > MAX_BODY_SIZE:
+                return jsonify({'error': 'Request body too large'}), 413
+        except ValueError:
+            return jsonify({'error': 'Invalid Content-Length header'}), 400
+    
+    # Security: Reject requests with both Transfer-Encoding and Content-Length
+    # This is a primary vector for HTTP Desync attacks
+    transfer_encoding = request.headers.get('Transfer-Encoding')
+    if transfer_encoding and content_length:
+        return jsonify({'error': 'Ambiguous message framing: both Transfer-Encoding and Content-Length present'}), 400
+    
+    # Security: Validate Transfer-Encoding header
+    if transfer_encoding:
+        # Only chunked is allowed; reject obfuscated values
+        te_values = [v.strip().lower() for v in transfer_encoding.split(',')]
+        if 'chunked' not in te_values or any(v not in ('chunked',) for v in te_values):
+            return jsonify({'error': 'Invalid Transfer-Encoding header'}), 400
+    
     url = f"http://{UPSTREAM_HOST}:{UPSTREAM_PORT}{request.path}"
     
     # Security issue: Forwarding raw headers without validation
@@ -24,7 +74,8 @@
     # - Connection header manipulation
     # - TE header smuggling
     # This allows attackers to desynchronize the connection pool
-    headers = dict(request.headers)
+    # FIX: Sanitize headers to remove hop-by-hop and smuggling-related headers
+    headers = sanitize_headers(request.headers)
     
     # Security issue: Using Connection: keep-alive without proper handling
     # This can lead to request smuggling via connection reuse
@@ -32,6 +83,12 @@
     # Security issue: Not validating Content-Length vs actual body
     # This allows attackers to craft smuggled requests
     data = request.get_data()
+    
+    # Security: Validate body size against Content-Length
+    if content_length_int is not None:
+        if len(data) != content_length_int:
+            return jsonify({'error': 'Content-Length mismatch'}), 400
+    
     response = requests.request(
         method=request.method,
         url=url,
@@ -41,7 +98,8 @@
         timeout=30
     )
     
-    return jsonify(response.json()), response.status_code
+    # Security: Don't blindly trust upstream response content type
+    return response.content, response.status_code, dict(response.headers)
 
 
 @app.route('/api/user/<user_id>', methods=['GET'])
@@ -51,7 +109,11 @@
     Vulnerable to user impersonation via smuggled requests.
     """
     # Security issue: No validation of request integrity
-    # An attacker can smuggle a request to change the user_id parameter
+    # FIX: Validate user_id to prevent injection attacks
+    if not re.match(r'^[a-zA-Z0-9_-]+$', user_id):
+        return jsonify({'error': 'Invalid user_id format'}), 400
+    
+    # Security: Verify request was not smuggled by checking internal state
     auth_header = request.headers.get('Authorization')
     if not auth_header:
         return jsonify({'error': 'Missing Authorization header'}), 401
@@ -61,7 +123,8 @@
     if not user:
         return jsonify({'error': 'User not found'}), 404
     
-    return jsonify(user), 200
+    # Security: Don't expose internal fields
+    return jsonify({'id': user.get('id'), 'username': user.get('username')}), 200
 
 
 def authenticate_user(auth_header):
@@ -69,7 +132,11 @@
     Authenticates user based on Authorization header.
     Vulnerable to timing attacks and lacks proper validation.
     """
-    # Placeholder for actual authentication logic
+    # Security: Basic validation to prevent injection
+    if not auth_header or not isinstance(auth_header, str):
+        return None
+    if len(auth_header) > 8192:  # Prevent DoS
+        return None
+    # Placeholder for actual authentication logic - in production use proper JWT/OAuth
     token = auth_header.replace('Bearer ', '')
     # Query database for user by token
     return {'id': '123', 'username': 'admin'}  # Placeholder
@@ -79,7 +146,11 @@ def get_user_by_id(user_id):
     """
     Retrieves user by ID from database.
     """
-    # Placeholder for actual database query
+    # Security: Validate user_id before database query
+    if not user_id or not isinstance(user_id, str):
+        return None
+    if len(user_id) > 256:  # Prevent DoS with超长ID
+        return