 ```diff
--- a/src
+++ b/src
@@ -0,0 +1,2 @@
+# This directory exists but we need to create the actual file
+# The fix will be in a new file: src/request_handler.py
--- a/src/request_handler.py
+++ b/src/request_handler.py
@@ -0,0 +1,168 @@
+"""
+Secure HTTP Request Handler
+Fixes HTTP Request Smuggling + Cache Poisoning vulnerabilities
+"""
+
+import re
+import hashlib
+from typing import Optional, Dict, List, Tuple
+from urllib.parse import unquote
+
+
+class SecureHTTPParser:
+    """
+    Secure HTTP parser that prevents HTTP Request Smuggling and Cache Poisoning.
+    """
+    
+    # Maximum header size to prevent DoS
+    MAX_HEADER_SIZE = 8192
+    MAX_HEADERS = 100
+    MAX_URI_LENGTH = 8192
+    
+    # Headers that can cause smuggling when duplicated or malformed
+    SINGLE_VALUE_HEADERS = {
+        'content-length', 'host', 'content-type', 'content-encoding',
+        'transfer-encoding', 'content-length', 'upgrade', 'connection'
+    }
+    
+    # Hop-by-hop headers that should not be forwarded
+    HOP_BY_HOP_HEADERS = {
+        'connection', 'keep-alive', 'proxy-authenticate',
+        'proxy-authorization', 'te', 'trailers', 'transfer-encoding', 'upgrade'
+    }
+    
+    def __init__(self):
+        self.cache = {}
+        self.cache_max_size = 1000
+    
+    def parse_request(self, raw_request: bytes) -> Dict:
+        """
+        Securely parse an HTTP request, preventing smuggling attacks.
+        """
+        if len(raw_request) > self.MAX_HEADER_SIZE * 2:
+            raise ValueError("Request too large")
+        
+        # Split headers from body
+        try:
+            header_part, _, body = raw_request.partition(b'\r\n\r\n')
+        except Exception:
+            header_part = raw_request
+            body = b''
+        
+        # Parse request line
+        lines = header_part.split(b'\r\n')
+        if not lines:
+            raise ValueError("Empty request")
+        
+        request_line = lines[0].decode('ascii', errors='replace')
+        method, uri, version = self._parse_request_line(request_line)
+        
+        # Validate URI
+        if len(uri) > self.MAX_URI_LENGTH:
+            raise ValueError("URI too long")
+        
+        # Parse headers securely
+        headers = self._parse_headers(lines[1:])
+        
+        # Detect and prevent smuggling
+        self._detect_smuggling(headers, body)
+        
+        # Normalize headers for cache key
+        cache_key = self._generate_cache_key(method, uri, headers, body)
+        
+        return {
+            'method': method,
+            'uri': uri,
+            'version': version,
+            'headers': headers,
+            'body': body,
+            'cache_key': cache_key,
+            'is_valid': True
+        }
+    
+    def _parse_request_line(self, line: str) -> Tuple[str, str, str]:
+        """Parse and validate the HTTP request line."""
+        parts = line.split(' ')
+        if len(parts) != 3:
+            raise ValueError("Invalid request line")
+        
+        method, uri, version = parts
+        
+        # Validate method: only allow safe characters
+        if not re.match(r'^[A-Z]+$', method):
+            raise ValueError("Invalid HTTP method")
+        
+        # Validate version
+        if not re.match(r'^HTTP/\d\.\d$', version):
+            raise ValueError("Invalid HTTP version")
+        
+        # Decode and validate URI
+        uri = unquote(uri)
+        if '\x00' in uri or '\n' in uri or '\r' in uri:
+            raise ValueError("Invalid characters in URI")
+        
+        return method, uri, version
+    
+    def _parse_headers(self, header_lines: List[bytes]) -> Dict[str, List[str]]:
+        """Parse headers with strict validation."""
+        headers: Dict[str, List[str]] = {}
+        
+        for line in header_lines:
+            if len(line) > self.MAX_HEADER_SIZE:
+                raise ValueError("Header line too long")
+            
+            # Parse header
+            if b':' not in line:
+                continue
+            
+            name, value = line.split(b':', 1)
+            name = name.decode('ascii', errors='replace').strip().lower()
+            value = value.decode('ascii', errors='replace').strip()
+            
+            # Remove dangerous characters
+            value = self._sanitize_header_value(value)
+            
+            # Check for single-value headers being duplicated
+            if name in self.SINGLE_VALUE_HEADERS:
+                if name in headers:
+                    raise ValueError(f"Duplicate header: {name}")
+            
+            if name not in headers:
+                headers[name] = []
+            headers[name].append(value)
+        
+        return headers
+    
+    def _sanitize_header_value(self, value: str) -> str:
+        """Remove dangerous characters from header values."""
+        # Remove null bytes and carriage returns
+        value = value.replace('\x00', '').replace('\r', '')
+        # Replace newlines with spaces to prevent header injection
+        value = value.replace('\n', ' ')
+        return value.strip()
+    
+    def _detect_smuggling(self, headers: Dict[str, List[str]], body: bytes) -> None:
+        """
+        Detect HTTP Request Smuggling attempts.
+        Raises ValueError if smuggling is detected.
+        """
+        # Check for both Content-Length and Transfer-Encoding
+        has_cl = 'content-length' in headers
+        has_te = 'transfer-encoding' in headers
+        
+        if has_cl and has_te:
+            # RFC 7230 Section 3.3.1: If Transfer-Encoding is present, 
+            # Content-Length must be ignored
+            # Reject requests with both to prevent smuggling
+            raise ValueError("Both Content-Length and Transfer-Encoding present")
+        
+        # Validate Content-Length
+        if has_cl:
+            cl_values = headers['content-length']
+            if len(cl_values) > 1:
+                raise ValueError("Multiple Content-Length headers")
+            try:
+                cl = int(cl_values[0])
+                if cl < 0:
+                    raise ValueError("Negative Content-Length")
+            except ValueError:
+                raise ValueError("Invalid Content-Length")
+        
+        # Validate Transfer-Encoding
+        if has_te:
+