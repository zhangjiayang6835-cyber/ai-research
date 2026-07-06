// Fix: Set HttpOnly flag when setting cookies in Node.js (Express)
const express = require('express');
const app = express();

app.get('/set-cookie', (req, res) => {
  // Secure cookie with HttpOnly flag
  res.cookie('session_id', 'abc123', {
    httpOnly: true,  // Prevents client-side script access
    secure: true,    // Send only over HTTPS
    sameSite: 'strict'  // CSRF protection
  });
  res.send('Cookie set securely');
});

app.listen(3000);
