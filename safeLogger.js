class SafeLogger {
  constructor(name) {
    this.name = name;
  }

  // Sanitize log message to prevent JNDI injection
  sanitizeMessage(msg) {
    // Remove any ${...} patterns that could be JNDI lookups
    return msg.replace(/\$\{[^}]*\}/g, '');
  }

  info(message, ...args) {
    const safeMsg = this.sanitizeMessage(message);
    console.log(`[INFO] [${this.name}] ${this.format(safeMsg, args)}`);
  }

  warn(message, ...args) {
    const safeMsg = this.sanitizeMessage(message);
    console.warn(`[WARN] [${this.name}] ${this.format(safeMsg, args)}`);
  }

  error(message, ...args) {
    const safeMsg = this.sanitizeMessage(message);
    console.error(`[ERROR] [${this.name}] ${this.format(safeMsg, args)}`);
  }

  format(message, args) {
    if (args.length === 0) return message;
    return message.replace(/{}/g, () => {
      const arg = args.shift();
      return arg !== undefined ? String(arg) : '{}';
    });
  }
}

module.exports = SafeLogger;
