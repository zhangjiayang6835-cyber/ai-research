const express = require('express');
const app = express();

app.get('/set-cookie', (req, res) => {
  res.cookie('session_id', 'abc123', { httpOnly: true, secure: true, sameSite: 'Lax' });
  res.send('Cookie set with HttpOnly flag');
});

app.listen(3000);