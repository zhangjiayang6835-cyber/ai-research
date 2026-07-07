"""
Secure logging framework with JNDI injection protection.
Fixes Log4j-style JNDI injection vulnerability by sanitizing log messages.
"""

import re
import logging
import sys


class JNDISanitizer:
    """
    Sanitizes log messages to prevent JNDI injection attacks.
    Blocks malicious JNDI lookup patterns like ${jndi:ldap://...}, ${jndi:dns://...}
    """
    
    # Pattern to match JNDI lookup expressions
    JNDI_PATTERN = re.compile(
        r'\$\{jndi:([^\}]+)\}',
        re.IGNORECASE
    )
    
    # Pattern to match other dangerous lookup patterns
    DANGEROUS_LOOKUPS = re.compile(
        r'\$\{(?:env|sys|java|lower|upper|env)::?([^\}]+)\}',
        re.IGNORECASE
    )
    
    @classmethod
    def sanitize(cls, message):
        """
        Sanitize a log message by removing JNDI injection payloads.
        
        Args:
            message: The log message to sanitize
            
        Returns:
            Sanitized string with JNDI payloads neutralized
        """
        if not isinstance(message, str):
            message = str(message)
        
        # Replace JNDI lookups with safe placeholder
        sanitized = cls.JNDI_PATTERN.sub('[BLOCKED-JNDI]', message)
        
        # Replace other potentially dangerous lookups
        sanitized = cls.DANGEROUS_LOOKUPS.sub('[BLOCKED-LOOKUP]', sanitized)
        
        return sanitized


class SecureLogger:
    """
    Secure logging wrapper that prevents JNDI injection attacks.
    """
    
    def __init__(self, name=None, level=logging.INFO):
        self.logger = logging.getLogger(name or __name__)
        self.logger.setLevel(level)
        
        # Add console handler if none exists
        if not self.logger.handlers:
            handler = logging.StreamHandler(sys.stdout)
            formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            )
            handler.setFormatter(formatter)
            self.logger.addHandler(handler)
    
    def _safe_log(self, level, message, *args, **kwargs):
        """Safely log a message after sanitizing."""
        if isinstance(message, str):
            message = JNDISanitizer.sanitize(message)
        self.logger.log(level, message, *args, **kwargs)
    
    def debug(self, message, *args, **kwargs):
        self._safe_log(logging.DEBUG, message, *args, **kwargs)
    
    def info(self, message, *args, **kwargs):
        self._safe_log(logging.INFO, message, *args, **kwargs)
    
    def warning(self, message, *args, **kwargs):
        self._safe_log(logging.WARNING, message, *args, **kwargs)
    
    def error(self, message, *args, **kwargs):
        self._safe_log(logging.ERROR, message, *args, **kwargs)
    
    def critical(self, message, *args, **kwargs):
        self._safe_log(logging.CRITICAL, message, *args, **kwargs)
    
    def exception(self, message, *args, **kwargs):
        self._safe_log(logging.ERROR, message, *args, **kwargs)