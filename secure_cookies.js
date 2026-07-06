/**
 * Express middleware to set secure cookie attributes to prevent cookie theft.
 * Should be applied to all routes that set cookies.
 */
function secureCookieMiddleware(req, res, next) {
    // Override res.cookie to enforce security flags
    const originalCookie = res.cookie.bind(res);
    res.cookie = function(name, value, options = {}) {
        // Enforce secure flags
        options.httpOnly = options.httpOnly !== false; // default true
        options.sameSite = options.sameSite || 'Lax';  // default Lax (or Strict)
        if (req.protocol === 'https') {
            options.secure = true;
        }
        // Also set cookie prefix __Host- for sensitive cookies (optional)
        return originalCookie(name, value, options);
    };
    next();
}

module.exports = secureCookieMiddleware;

// Example usage in an Express app:
// const express = require('express');
// const secureCookie = require('./secure_cookies');
// const app = express();
// app.use(secureCookie);
// app.get('/', (req, res) => {
//     res.cookie('session', 'some-token', { maxAge: 3600000 });
//     res.send('OK');
// });
