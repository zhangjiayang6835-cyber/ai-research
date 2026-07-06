const express = require('express');
const crypto = require('crypto');

const app = express();
const PORT = 3000;

// Bad practice: session token in URL
// Example: /data?token=abc123
// app.get('/data', (req, res) => {
//     const token = req.query.token;
//     // validate token...
//     res.json({ data: 'secret' });
// });

// Good practice: use Authorization header with Bearer token
app.get('/data', (req, res) => {
    const authHeader = req.headers['authorization'];
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ error: 'Missing or invalid token' });
    }
    const token = authHeader.split(' ')[1];
    // validate token...
    res.json({ data: 'secret' });
});

app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});