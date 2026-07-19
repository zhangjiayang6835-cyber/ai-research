const express = require('express');
const app = express();

app.use((req, res, next) => {
    // Set X-Frame-Options to DENY
    res.setHeader('X-Frame-Options', 'DENY');

    // Set Content-Security-Policy to frame-ancestors 'none'
    res.setHeader('Content-Security-Policy', "frame-ancestors 'none'");

    next();
});

// Your existing routes
app.get('/withdrawal', (req, res) => {
    res.send('<h1>Asset Withdrawal Page</h1>');
});

app.listen(3000, () => {
    console.log('Server is running on port 3000');
});