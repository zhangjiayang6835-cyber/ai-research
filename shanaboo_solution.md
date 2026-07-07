 ```diff
--- a/src/logger.py
+++ b/src/logger.py
@@ -0,0 +1,85 @@
+"""
+Secure logging framework with JNDI injection vulnerability fix.
+This module provides a safe logging implementation that prevents
+Log4j-style JNDI injection attacks by sanitizing log messages.
+"""
+
+import re
+import logging
+import sys
+from typing import Optional
+
+
+class JNDISanitizer:
+    """
+    Sanitizes log messages to prevent JNDI injection attacks.
+    Blocks patterns like ${jndi:ldap://...}, ${jndi:dns://...}, etc.
+    """
+    
+    # Pattern to match JNDI lookup syntax: ${jndi:...}
+    JNDI_PATTERN = re.compile(
+        r'\$\{jndi:[^}]*\}',
+        re.IGNORECASE
+    )
+    
+    # Pattern to match other dangerous lookup patterns
+    DANGEROUS_LOOKUPS = re.compile(
+        r'\$\{(?:env|sys|java|ctx|bundle|lower|upper|date|main):\s*[^}]*\}',
+        re.IGNORECASE
+    )
+    
+    # Blocked protocols in JNDI
+    BLOCKED_PROTOCOLS = {'ldap', 'ldaps', 'rmi', 'dns', 'iiop', 'corba', 'http', 'https', 'nis'}
+    
+    @classmethod
+    def sanitize(cls, message: str) -> str:
+        """
+        Sanitize a log message by removing JNDI injection payloads.
+        
+        Args:
+            message: The raw log message
+            
+        Returns:
+            Sanitized message with JNDI payloads removed
+        """
+        if not isinstance(message, str):
+            message = str(message)
+        
+        # Replace JNDI patterns with [BLOCKED]
+        sanitized = cls.JNDI_PATTERN.sub('[BLOCKED]', message)
+        
+        # Also block other potentially dangerous lookups
+        sanitized = cls.DANGEROUS_LOOKUPS.sub('[BLOCKED]', sanitized)
+        
+        return sanitized
+    
+    @classmethod
+    def contains_jndi(cls, message: str) -> bool:
+        """
+        Check if a message contains JNDI injection patterns.
+        
+        Args:
+            message: The message to check
+            
+        Returns:
+            True if JNDI pattern is detected
+        """
+        if not isinstance(message, str):
+            message = str(message)
+        
+        # Check for JNDI pattern
+        if cls.JNDI_PATTERN.search(message):
+            return True
+        
+        # Check for blocked protocols in potential JNDI strings
+        lower_msg = message.lower()
+        for protocol in cls scarl_PROTOCOLS:
+            if f'jndi:{protocol}:' in lower_msg or f'jndi:{protocol}://' in lower_msg:
+                return True
+        
+        return False
+
+
+class SecureLogger:
+    """
+    A secure logging class that prevents JNDI injection attacks.
+    Wraps Python's standard logging with input sanitization.
+    """
+    
+    def __init__(self, name: str, level: int = logging.INFO):
+        self.logger = logging.getLogger(name)
+        self.logger.setLevel(level)
+        
+        # Create console handler if no handlers exist
+        if not self.logger.handlers:
+            handler = logging.StreamHandler(sys.stdout)
+            handler.setLevel(level)
+            formatter = logging.Formatter(
+                '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
+            )
+            handler.setFormatter(formatter)
+            self.logger.addHandler(handler)
+    
+    def _sanitize_args(self, msg, *args, **kwargs):
+        """Sanitize message and arguments before logging."""
+        if isinstance(msg, str):
+            msg = JNDISanitizer.sanitize(msg)
+        
+        # Sanitize format arguments
+        if args:
+            args = tuple(
+                JNDISanitizer.sanitize(arg) if isinstance(arg, str) else arg 
+                for arg in args
+            )
+        
+        if kwargs:
+            kwargs = {
+                k: JNDISanitizer.sanitize(v) if isinstance(v, str) else v
+                for k, v in kwargs.items()
+            }
+        
+        return msg, args, kwargs
+    
+    def debug(self, msg, *args, **kwargs):
+        """Log debug message with sanitization."""
+        msg, args, kwargs = self._sanitize_args(msg, *args, **kwargs)
+        self.logger.debug(msg, *args, **kwargs)
+    
+    def info(self, msg, *args, **kwargs):
+        """Log info message with sanitization."""
+        msg, args, kwargs = self._sanitize_args(msg, *args, **kwargs)
+        self.logger.info(msg, *args, **kwargs)
+    
+    def warning(self, msg, *args, **kwargs):
+        """Log warning message with sanitization."""
+        msg, args, kwargs = self._sanitize_args(msg, *args, **kwargs)
+        self.logger.warning(msg, *args, **kwargs)
+    
+    def error(self, msg, *args, **kwargs):
+        """Log error message with sanitization."""
+        msg, args, kwargs = self._sanitize_args(msg, *args, **kwargs)
+        self.logger.error(msg, *args, **kwargs)
+    
+    def critical(self, msg, *args, **kwargs):
+        """Log critical message with sanitization."""
+        msg, args, kwargs = self._sanitize_args(msg, *args, **kwargs)
+        self.logger.critical(msg, *args, **kwargs)
+    
+    def exception(self, msg, *args, **kwargs):
+        """Log exception message with sanitization."""
+        msg, args, kwargs = self._sanitize_args(msg, *args, **kwargs)
+        self.logger.exception(msg, *args, **kwargs)
+
+
+# Global secure logger instance
+_secure_logger: Optional[SecureLogger] = None
+
+
+def get_secure_logger(name: str = "secure_app", level: int = logging.INFO) -> SecureLogger:
+    """
+    Get or create a secure logger instance.
+    
+    Args:
+        name: Logger name
+        level: Logging level
+        
+    Returns:
+        SecureLogger instance
+    """
+    global _secure_logger
+    if _secure_logger is None:
+        _secure_logger = SecureLogger(name, level)
+    return _secure_logger
+
+
+# Convenience functions for direct logging
+def secure_log(level: str, message: str, *args, **kwargs):
+    """
+   