Based on the issue description, this is about fixing HTTP Request Smuggling (CL.TE) vulnerability. The fix needs to be in the nginx configuration or a proxy/middleware component. Since the repo structure shows `honeycode-honeypot` as a submodule and various fix files, I need to create a fix that addresses the HTTP parsing ambiguity.

Let me check the existing fix files for patterns and create a proper solution.

```diff
--- /dev/null
+++ b/fix-cl-te-smuggling.py
@@ -0,0 +1,198 @@
+#!/usr/bin/env python3
+"""
+CL.TE HTTP Request Smuggling → Cache Poisoning Fix
+
+This module implements a unified HTTP request parser that rejects
+ambiguous requests where both Content-Length and Transfer-Encoding
+headers are present, preventing HTTP request smuggling attacks.
+
+Implements:
+  - RFC 7230 Section 3.3.3 compliance: If both CL and TE present, reject (400)
+  - Strict Transfer-Encoding validation (reject malformed chunked encoding)
+  - HTTP/2 upgrade preference to eliminate parsing ambiguity
+  - Reject HTTP/1.0 downgrade requests that bypass chunked parsing
+"""
+
+import re
+import logging
+from typing import Optional, Tuple, Dict, List
+from dataclasses import dataclass, field
+
+logger = logging.getLogger(__name__)
+
+
+@dataclass
+class ParsedRequest:
+    """Unified parsed HTTP request representation."""
+    method: str
+    path: str
+    version: str
+    headers: Dict[str, str] = field(default_factory=dict)
+    body: bytes = b""
+    is_valid: bool = True
+    error_reason: Optional[str] = None
+
+
+class UnifiedHTTPParser:
+    """
+    Unified HTTP request parser that eliminates CL.TE ambiguity.
+
+    This parser enforces strict RFC 7230 compliance:
+    - If both Content-Length and Transfer-Encoding are present,
+      the request MUST be rejected with 400 Bad Request.
+    - Transfer-Encoding: chunked must be properly formatted.
+    - HTTP/1.0 requests cannot use Transfer-Encoding: chunked
+      (prevents downgrade smuggling).
+    """
+
+    # Regex for parsing request line
+    REQUEST_LINE_RE = re.compile(
+        rb"^([A-Z]+) ([^\s]+) HTTP/(1\.[01]|2\.0)\r\n"
+    )
+
+    # Regex for header lines
+    HEADER_RE = re.compile(rb"^([^:]+):\s*(.+?)\r\n")
+
+    # Valid Transfer-Encoding tokens
+    VALID_TE_TOKENS = {"chunked", "compress", "deflate", "gzip", "identity"}
+
+    # Chunked body parsing states
+    CHUNK_SIZE_RE = re.compile(rb"^([0-9a-fA-F]+)(?:;[^\r\n]*)?\r\n")
+
+    def __init__(self, max_body_size: int = 10 * 1024 * 1024):
+        """
+        Initialize the unified parser.
+
+        Args:
+            max_body_size: Maximum allowed body size in bytes (default 10MB)
+        """
+        self.max_body_size = max_body_size
+
+    def parse_request(self, raw_data: bytes) -> ParsedRequest:
+        """
+        Parse a raw HTTP request into a unified representation.
+
+        Args:
+            raw_data: Raw bytes of the HTTP request
+
+        Returns:
+            ParsedRequest with validation results
+        """
+        try:
+            # Split headers from body
+            header_end = raw_data.find(b"\r\n\r\n")
+            if header_end == -1:
+                return ParsedRequest(
+                    method="", path="", version="",
+                    is_valid=False,
+                    error_reason="No CRLF CRLF found"
+                )
+
+            header_section = raw_data[:header_end]
+            body_start = header_end + 4
+
+            # Parse request line
+            first_crlf = header_section.find(b"\r\n")
+            if first_crlf == -1:
+                return ParsedRequest(
+                    method="", path="", version="",
+                    is_valid=False,
+                    error_reason="No request line found"
+                )
+
+            request_line = header_section[:first_crlf]
+            match = self.REQUEST_LINE_RE.match(request_line)
+            if not match:
+                return ParsedRequest(
+                    method="", path="", version="",
+                    is_valid=False,
+                    error_reason="Invalid request line"
+                )
+
+            method = match.group(1).decode("ascii", errors="replace")
+            path = match.group(2).decode("ascii", errors="replace")
+            version = f"HTTP/{match.group(3).decode('ascii')}"
+
+            # Parse headers
+            headers = {}
+            remaining = header_section[first_crlf + 2:]
+            pos = 0
+            while pos < len(remaining):
+                hdr_match = self.HEADER_RE.match(remaining[pos:])
+                if not hdr_match:
+                    break
+                name = hdr_match.group(1).decode("ascii", errors="replace").lower()
+                value = hdr_match.group(2).decode("ascii", errors="replace").strip()
+                headers[name] = value
+                pos += hdr_match.end()
+
+            # === CRITICAL FIX: CL.TE Ambiguity Detection ===
+            has_content_length = "content-length" in headers
+            has_transfer_encoding = "transfer-encoding" in headers
+
+            # RFC 7230 Section 3.3.3: If both CL and TE present, REJECT
+            if has_content_length and has_transfer_encoding:
+                return ParsedRequest(
+                    method=method, path=path, version=version,
+                    headers=headers,
+                    is_valid=False,
+                    error_reason=(
+                        "HTTP Request Smuggling detected: "
+                        "Both Content-Length and Transfer-Encoding present. "
+                        "Request rejected per RFC 7230 Section 3.3.3."
+                    )
+                )
+
+            # Validate Transfer-Encoding if present
+            if has_transfer_encoding:
+                te_value = headers["transfer-encoding"]
+                if not self._validate_transfer_encoding(te_value, version):
+                    return ParsedRequest(
+                        method=method, path=path