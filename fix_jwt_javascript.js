const jwt = require('jsonwebtoken');

/**
 * Securely verify a JWT token using the RS256 algorithm.
 * This prevents algorithm confusion and key injection attacks.
 */
function verifyJwt(token, publicKey) {
    try {
        // Explicitly specify the allowed algorithms; never trust the header's 'alg' field.
        const payload = jwt.verify(token, publicKey, { algorithms: ['RS256'] });
        return payload;
    } catch (err) {
        if (err.name === 'TokenExpiredError') {
            throw new Error('Token has expired');
        } else {
            throw new Error(`Invalid token: ${err.message}`);
        }
    }
}

// Example usage:
// const fs = require('fs');
// const publicKey = fs.readFileSync('public.pem', 'utf8');
// try {
//     const data = verifyJwt(token, publicKey);
//     console.log(data);
// } catch (e) {
//     console.error(e.message);
// }
