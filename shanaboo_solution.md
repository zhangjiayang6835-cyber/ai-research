 ```diff
--- a/src
+++ b/src
@@ -0,0 +1,1 @@
+/* This directory exists but no relevant files were shown */
--- /dev/null
+++ b/fix-http-request-smuggling.py
@@ -0,0 +1,156 @@
+#!/usr/bin/env python3
+"""
+HTTP Request Smuggling + Cache Poisoning Fix
+
+This module provides secure HTTP parsing and request handling to prevent
+HTTP Request Smuggling (HRS) and Cache Poisoning attacks.
+
+Vulnerabilities addressed:
+1. CL.TE (Content-Length + Transfer-Encoding) smuggling
+2. TE.CL smuggling
+3. TE.TE smuggling with obfuscated headers
+4. Double Content-Length headers
+5. Chunked encoding abuse
+"""
+
+import re
+from typing import Optional, Dict, List, Tuple, Union
+
+
+class HTTPParserError(Exception):
+    """Raised when an HTTP parsing security violation is detected."""
+    pass
+
+
+class HTTPRequestSmugglingDetector:
+    """
+    Detects and prevents HTTP Request Smuggling attacks.
+    
+    Implements defenses against:
+    - CL.TE attacks
+    - TE.CL attacks  
+    - TE.TE attacks with header obfuscation
+    - Double Content-Length
+    - Chunked encoding anomalies
+    """
+    
+    # Transfer-Encoding header variations used for obfuscation
+    TE_OBFUSCATED_PATTERNS = [
+        b'transfer-encoding',
+        b'transfer_encoding',
+        b'transfer+encoding',
+        b'transfer encoding',
+        b'transfer-encoding:',
+        b'transfer-encoding\x00',
+        b'transfer-encoding\x0b',
+        b'transfer-encoding\x0c',
+        b'transfer-encoding ',
+    ]
+    
+    # Chunk size patterns that could indicate attacks
+    CHUNK_ATTACK_PATTERNS = [
+        b';',  # chunk-ext with semicolon can cause parsing differences
+    ]
+    
+    def __init__(self, max_headers: int = 100, max_header_size: int = 8192):
+        self.max_headers = max_headers
+        self.max_header_size = max_header_size
+    
+    def parse_request(self, raw_request: bytes) -> Dict:
+        """
+        Securely parse an HTTP request, detecting smuggling attempts.
+        
+        Args:
+            raw_request: Raw HTTP request bytes
+            
+        Returns:
+            Parsed request dictionary
+            
+        Raises:
+            HTTPParserError: If smuggling attempt detected
+        """
+        if len(raw_request) > 1024 * 1024:  # 1MB max
+            raise HTTPParserError("Request too large")
+        
+        # Split headers from body
+        try:
+            header_end = raw_request.index(b'\r\n\r\n')
+        except ValueError:
+            try:
+                header_end = raw_request.index(b'\n\n')
+            except ValueError:
+                header_end = len(raw_request)
+        
+        headers_raw = raw_request[:header_end]
+        body = raw_request[header_end + 4 if b'\r\n\r\n' in raw_request else header_end + 2:]
+        
+        # Parse request line
+        lines = headers_raw.split(b'\r\n')
+        if len(lines) == 1:
+            lines = headers_raw.split(b'\n')
+        
+        if not lines or not lines[0]:
+            raise HTTPParserError("Empty request")
+        
+        request_line = lines[0].decode('ascii', errors='replace')
+        
+        # Parse headers securely
+        headers: Dict[str, List[str]] = {}
+        for line in lines[1:]:
+            if not line:
+                continue
+            if len(line) > self.max_header_size:
+                raise HTTPParserError("Header too large")
+            
+            # Find colon separator
+            if b':' not in line:
+                continue
+            
+            name, value = line.split(b':', 1)
+            name_str = name.strip().decode('ascii', errors='replace').lower()
+            value_str = value.strip().decode('ascii', errors='replace')
+            
+            if name_str not in headers:
+                headers[name_str] = []
+            headers[name_str].append(value_str)
+        
+        # Detect smuggling attempts
+        self._detect_smuggling(headers, body)
+        
+        return {
+            'request_line': request_line,
+            'headers': headers,
+            'body': body
+        }
+    
+    def _detect_smuggling(self, headers: Dict[str, List[str]], body: bytes) -> None:
+        """
+        Detect HTTP request smuggling attempts.
+        
+        Args:
+            headers: Parsed headers dictionary
+            body: Request body
+            
+        Raises:
+            HTTPParserError: If smuggling detected
+        """
+        has_content_length = 'content-length' in headers
+        has_transfer_encoding = 'transfer-encoding' in headers
+        
+        # Check for double Content-Length
+        if has_content_length and len(headers.get('content-length', [])) > 1:
+            raise HTTPParserError("Double Content-Length header detected")
+        
+        # Check for conflicting Content-Length and Transfer-Encoding
+        if has_content_length and has_transfer_encoding:
+            # RFC 7230 Section 3.3.1: When both present, Transfer-Encoding takes precedence
+            # But for security, we should reject or carefully handle
+            te_values = headers.get('transfer-encoding', [])
+            if te_values and 'chunked' in te_values[-1].lower():
+                # TE.CL conflict - potential smuggling
+                raise HTTPParserError("CL.TE smuggling attempt detected: both Content-Length and Transfer-Encoding: chunked present")
+        
+        # Check for obfuscated Transfer-Encoding
+        for header_name in headers.keys():
+            decoded = header_name.encode('ascii', errors='replace').lower()
+            # Check for non-standard characters in header name
+            if any(c > 127 or c < 32 for c in decoded):
+                raise HTTPParserError("Non-ASCII characters in header name - potential smuggling")
+        
+        # Validate Transfer-Encoding value
+        if has_transfer_encoding:
+            te = headers.get('transfer-encoding', [''])[-1].lower()
+            # Check for multiple encodings that could confuse parsers
+            if te.count('chunked') > 1:
+                raise HTTPParserError("Multiple chunked in Transfer-Encoding")
+            # chunked must be last
+            encodings = [e.strip() for e in te.split(',')]
+            if 'chunked' in encodings and encodings[-