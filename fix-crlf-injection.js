/**
 * Fix: CRLF Injection in Access Log → HTTP Response Splitting
 * 
 * Vulnerability: User-Agent header value is written directly to response headers
 * via res.setHeader("X-Log", userAgent), allowing CRLF injection attacks.
 * 
 * Fix: Sanitize user input by stripping \r and \n characters and encoding
 * the value before setting it in response headers.
 */

/**
 * Sanitizes a string for safe use in HTTP response headers.
 * - Removes CR (\r) and LF (\n) characters to prevent HTTP response splitting
 * - Encodes the value using encodeURIComponent for additional safety
 * - Trims whitespace
 * 
 * @param {string} input - The user-supplied input (e.g., User-Agent)
 * @returns {string} - Sanitized string safe for HTTP headers
 */
function sanitizeHeaderValue(input) {
  if (typeof input !== 'string') {
    return '';
  }
  
  // Step 1: Remove CRLF characters to prevent response splitting
  let sanitized = input.replace(/[\r\n]+/g, ' ');
  
  // Step 2: Encode the value for header safety
  sanitized = encodeURIComponent(sanitized);
  
  // Step 3: Trim whitespace
  sanitized = sanitized.trim();
  
  return sanitized;
}

// USAGE EXAMPLE - Replace vulnerable code:
// BEFORE (VULNERABLE):
//   const userAgent = req.headers['user-agent'] || 'unknown';
//   res.setHeader('X-Log', userAgent);  // CRLF injection possible!
//
// AFTER (FIXED):
//   const userAgent = req.headers['user-agent'] || 'unknown';
//   const safeUserAgent = sanitizeHeaderValue(userAgent);
//   res.setHeader('X-Log', safeUserAgent);  // Safe - CRLF characters removed & encoded

module.exports = { sanitizeHeaderValue };