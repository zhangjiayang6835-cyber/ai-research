const express = require('express');
const session = require('express-session');
const crypto = require('crypto');
const app = express();

// Middleware to parse JSON bodies
app.use(express.json());

// Session middleware
app.use(session({
  secret: 'your_secret_key', // Replace with your actual secret key
  resave: false,
  saveUninitialized: true,
}));

// Route to initiate OAuth process
app.get('/oauth/init', (req, res) => {
  // Generate a 16-byte (or more) random state token
  const stateToken = crypto.randomBytes(16).toString('hex');

  // Store the state token in the session
  req.session.oauthState = stateToken;

  // Redirect to the OAuth provider with the state token
  const oauthUrl = `https://oauth-provider.com/oauth?client_id=YOUR_CLIENT_ID&redirect_uri=YOUR_REDIRECT_URI&state=${stateToken}`;
  res.redirect(oauthUrl);
});

// Callback route to handle the OAuth response
app.get('/oauth/callback', (req, res) => {
  const { code, state } = req.query;

  // Verify the state token
  if (req.session.oauthState && req.session.oauthState === state) {
    // State token is valid and matches the one in the session
    // Proceed with exchanging the code for an access token
    //...

    // Clear the state token from the session to ensure single use
    delete req.session.oauthState;

    res.send('OAuth successful!');
  } else {
    // State token is invalid or does not match
    res.status(400).send('Invalid state token');
  }
});

// Start the server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});