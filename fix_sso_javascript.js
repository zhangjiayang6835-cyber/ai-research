const jwt = require('jsonwebtoken');
const jwksClient = require('jwks-rsa');

/**
 * Validates a federated SSO token and ensures it matches the expected tenant.
 * Prevents cross-tenant account takeover by verifying the token's issuer and tenant.
 */
async function validateSsoToken(token, expectedIssuer, expectedTenantId) {
  try {
    // Decode without verification to check claims
    const decoded = jwt.decode(token, { complete: true });
    if (!decoded) {
      throw new Error('Invalid token');
    }
    
    // Check issuer
    if (decoded.payload.iss !== expectedIssuer) {
      throw new Error('Invalid token issuer');
    }
    
    // Check tenant (tid or tenant claim)
    if (decoded.payload.tid !== expectedTenantId && decoded.payload.tenant !== expectedTenantId) {
      throw new Error('Invalid tenant');
    }

    // Get signing key from issuer's JWKS endpoint
    const client = jwksClient({ jwksUri: `${expectedIssuer}/.well-known/jwks.json` });
    const key = await client.getSigningKey(decoded.header.kid);
    const signingKey = key.getPublicKey();

    // Verify signature and other claims
    const verified = jwt.verify(token, signingKey, {
      algorithms: ['RS256'],
      issuer: expectedIssuer,
      audience: expectedIssuer  // or your app's client ID
    });
    return verified;
  } catch (error) {
    throw error;
  }
}

// Example usage in Express route
app.get('/sso/callback', async (req, res) => {
  const token = req.query.token;
  if (!token) {
    return res.status(400).send('Token missing');
  }
  try {
    const expectedIssuer = 'https://your-idp.com/';
    const expectedTenantId = 'your-tenant-id';
    const userInfo = await validateSsoToken(token, expectedIssuer, expectedTenantId);
    res.send(`Welcome ${userInfo.sub}`);
  } catch (err) {
    res.status(401).send(err.message);
  }
});
