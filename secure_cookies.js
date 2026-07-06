// Express.js middleware to harden cookie security
const secureCookie = (req, res, next) => {
    res.cookie = function(name, value, options = {}) {
        // Default secure cookie options
        const secureOptions = {
            httpOnly: true,
            secure: true,
            sameSite: 'strict',
            ...options
        };
        // Use the native res.cookie method with overridden options
        return res.cookie.call(res, name, value, secureOptions);
    };
    next();
};

module.exports = secureCookie;

// Usage in app:
// const express = require('express');
// const secureCookie = require('./secure_cookies');
// const app = express();
// app.use(secureCookie);
// Now all cookies set via res.cookie() will have secure defaults.
