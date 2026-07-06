const express = require('express');
const app = express();

// Before: token in URL query, e.g., /api/resource?session_token=abc123
// After: use Authorization header or secure cookie

function secureGetToken(req) {
    // 1. Check Authorization header
    const authHeader = req.headers.authorization;
    if (authHeader && authHeader.startsWith('Bearer ')) {
        return authHeader.substring(7);
    }
    // 2. Check secure cookie (HttpOnly, Secure, SameSite)
    if (req.cookies && req.cookies.session_token) {
        return req.cookies.session_token;
    }
    // 3. Reject if token is in URL query (vulnerable)
    if (req.query.session_token) {
        throw new Error('Session token in URL is not allowed. Use Authorization header or secure cookie.');
    }
    return null;
}

app.get('/api/resource', (req, res) => {
    let token;
    try {
        token = secureGetToken(req);
    } catch (err) {
        return res.status(400).json({ error: err.message });
    }
    if (!token) {
        return res.status(401).json({ error: 'Missing or invalid session token' });
    }
    // Validate token...
    res.json({ message: 'Resource accessed securely' });
});

app.listen(3000, () => console.log('Server running on port 3000'));
