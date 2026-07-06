const jwt = require('jsonwebtoken');

// Vulnerable code:
// const decoded = jwt.verify(token, publicKey, { algorithms: ['HS256', 'RS256'] });

// Fixed code:
function verifyJwt(token, publicKey) {
    try {
        // Only allow RS256 algorithm
        const payload = jwt.verify(token, publicKey, { algorithms: ['RS256'] });
        return payload;
    } catch (err) {
        if (err instanceof jwt.TokenExpiredError) {
            throw err;
        }
        throw new Error('Invalid token: ' + err.message);
    }
}

// Additional: Ensure that the key is an RSA public key
const crypto = require('crypto');

function loadPublicKey(keyContent) {
    const key = crypto.createPublicKey(keyContent);
    if (key.asymmetricKeyType !== 'rsa') {
        throw new TypeError('Key must be an RSA public key');
    }
    return key;
}
