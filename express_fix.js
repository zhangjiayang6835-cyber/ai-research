const express = require('express');
const session = require('express-session');
const crypto = require('crypto');

const app = express();

app.use(session({
  secret: crypto.randomBytes(32).toString('hex'),
  resave: false,
  saveUninitialized: true,
  cookie: { httpOnly: true, secure: true }
}));

// Prevent caching for all responses
app.use((req, res, next) => {
  res.set({
    'Cache-Control': 'no-store, no-cache, must-revalidate, private',
    'Pragma': 'no-cache',
    'Expires': '0'
  });
  next();
});

app.get('/login', (req, res) => {
  res.send(`
    <form method="post">
      <input type="text" name="username" placeholder="Username">
      <input type="password" name="password" placeholder="Password">
      <button type="submit">Login</button>
    </form>
  `);
});

app.post('/login', (req, res) => {
  // Authenticate (simplified)
  if (req.body.username === 'admin' && req.body.password === 'secret') {
    // Regenerate session to prevent fixation
    req.session.regenerate((err) => {
      if (err) return res.status(500).send('Error');
      req.session.user = 'admin';
      res.redirect('/dashboard');
    });
  } else {
    res.redirect('/login');
  }
});

app.get('/dashboard', (req, res) => {
  if (!req.session.user) return res.redirect('/login');
  res.send('Welcome!');
});

app.listen(3000, () => console.log('Server running on port 3000'));