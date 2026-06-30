 ```diff
--- /dev/null
+++ b/honeycode-honeypot/graphql_security.py
@@ -0,0 +1,218 @@
+"""
+GraphQL Security Middleware
+Provides depth limiting and batching protection against data exfiltration attacks.
+"""
+
+import json
+import re
+from typing import Any, Callable, Dict, List, Optional, Union
+from functools import wraps
+
+
+class GraphQLSecurityError(Exception):
+    """Raised when a GraphQL security violation is detected."""
+    pass
+
+
+class QueryDepthLimiter:
+    """
+    Limits the maximum depth of GraphQL queries to prevent deep recursion attacks.
+    """
+    
+    def __init__(self, max_depth: int = 10):
+        self.max_depth = max_depth
+    
+    def _parse_query_depth(self, query: str) -> int:
+        """
+        Calculate the depth of a GraphQL query by analyzing nested structures.
+        """
+        # Remove strings to avoid counting braces inside them
+        query = re.sub(r'"(?:\\.|[^"\\])*"', '""', query)
+        query = re.sub(r'\'(?:\\.|[^\'\\])*\'', "''", query)
+        
+        depth = 0
+        max_depth = 0
+        in_query = False
+        
+        # Simple brace counting for nested structures
+        i = 0
+        while i < len(query):
+            char = query[i]
+            
+            # Skip comments
+            if char == '#' and not in_query:
+                while i < len(query) and query[i] != '\n':
+                    i += 1
+                continue
+            
+            if char == '{':
+                if not in_query:
+                    in_query = True
+                depth += 1
+                max_depth = max(max_depth, depth)
+            elif char == '}':
+                depth -= 1
+                if depth == 0:
+                    in_query = False
+            
+            i += 1
+        
+        return max_depth
+    
+    def check_depth(self, query: str) -> bool:
+        """
+        Check if query depth exceeds maximum allowed depth.
+        Returns True if query is safe, raises GraphQLSecurityError otherwise.
+        """
+        depth = self._parse_query_depth(query)
+        if depth > self.max_depth:
+            raise GraphQLSecurityError(
+                f"Query depth ({depth}) exceeds maximum allowed depth ({self.max_depth}). "
+                f"This may indicate a depth bypass attack."
+            )
+        return True
+
+
+class BatchLimiter:
+    """
+    Limits the number of operations in a batch request to prevent batching attacks.
+    """
+    
+    def __init__(self, max_batch_size: int = 5):
+        self.max_batch_size = max_batch_size
+    
+    def check_batch_size(self, queries: List[Any]) -> bool:
+        """
+        Check if batch size exceeds maximum allowed.
+        Returns True if batch is safe, raises GraphQLSecurityError otherwise.
+        """
+        if len(queries) > self.max_batch_size:
+            raise GraphQLSecurityError(
+                f"Batch size ({len(queries)}) exceeds maximum allowed ({self.max_batch_size}). "
+                f"This may indicate a batching attack."
+            )
+        return True
+
+
+class GraphQLSecurityMiddleware:
+    """
+    Combined security middleware for GraphQL that protects against:
+    - Depth bypass attacks (deeply nested queries)
+    - Batching attacks (multiple queries in single request)
+    """
+    
+    def __init__(
+        self,
+        max_depth: int = 10,
+        max_batch_size: int = 5,
+        enable_logging: bool = True
+    ):
+        self.depth_limiter = QueryDepthLimiter(max_depth=max_depth)
+        self.batch_limiter = BatchLimiter(max_batch_size=max_batch_size)
+        self.enable_logging = enable_logging
+    
+    def validate_request(self, request_data: Union[Dict, List, str]) -> None:
+        """
+        Validate a GraphQL request for security issues.
+        
+        Args:
+            request_data: The GraphQL request, can be a single query dict,
+                         a list of queries (batch), or a query string.
+        
+        Raises:
+            GraphQLSecurityError: If security violation is detected.
+        """
+        # Handle batch requests
+        if isinstance(request_data, list):
+            self.batch_limiter.check_batch_size(request_data)
+            for query in request_data:
+                self._validate_single_query(query)
+        else:
+            self._validate_single_query(request_data)
+    
+    def _validate_single_query(self, query_data: Union[Dict, str]) -> None:
+        """
+        Validate a single GraphQL query.
+        """
+        if isinstance(query_data, dict):
+            query = query_data.get('query', '')
+        else:
+            query = str(query_data)
+        
+        self.depth_limiter.check_depth(query)
+
+
+def secure_graphql_handler(
+    max_depth: int = 10,
+    max_batch_size: int = 5
+) -> Callable:
+    """
+    Decorator to secure GraphQL handlers.
+    
+    Usage:
+        @secure_graphql_handler(max_depth=10, max_batch_size=5)
+        def graphql_endpoint(request):
+            # Your handler code
+            pass
+    """
+    middleware = GraphQLSecurityMiddleware(
+        max_depth=max_depth,
+        max_batch_size=max_batch_size
+    )
+    
+    def decorator(func: Callable) -> Callable:
+        @wraps(func)
+        def wrapper(*args, **kwargs):
+            # Extract request from args/kwargs
+            request = kwargs.get('request')
+            if request is None and args:
+                request = args[0]
+            
+            if request is not None:
+                # Try to get request data
+                try:
+                    if hasattr(request, 'json'):
+                        data = request.json()
+                    elif hasattr(request, 'body'):
+                        data = json.loads(request.body)
+                    elif hasattr(request, 'get_json'):
+                        data = request.get_json()
+                    else:
+                        data = request
+                except (AttributeError, json.JSONDecodeError):
+                    data = request
+                
+                # Validate the request
+                middleware.validate_request(data)
+            
+            return func(*args, **kwargs)
+        return wrapper
+    return decorator
+
+
+# Default security configurations
+DEFAULT_MAX_DEPTH = 10
+DEFAULT_MAX_BATCH_SIZE = 5
+
+
+def create_secure_middleware(
+    max_depth: int = DEFAULT_MAX_DEPTH,
+    max_batch_size: int = DEFAULT