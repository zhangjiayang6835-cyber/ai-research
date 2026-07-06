const jwt = require('jsonwebtoken');

/**
 * Verify a JWT token with a fixed algorithm whitelist.
 * Prevents algorithm confusion and key injection attacks.
 *
 * @param {string} token - The JWT token.
 * @param {string|Buffer} secretOrKey - The secret (for HMAC) or public key (for RSA/ECDSA).
 * @param {string[]} allowedAlgorithms - List of allowed algorithms, e.g. ['HS256'].
 * @returns {object} Decoded payload.
 * @throws {Error} If verification fails.
 */
function verifyJWT(token, secretOrKey, allowedAlgorithms = ['HS256']) {
    // Decode header without verification to get algorithm
    const decodedHeader = jwt.decode(token, { complete: true, json: true });
    if (!decodedHeader) {
        throw new Error('Invalid token: unable to decode header');
    }
    const tokenAlg = decodedHeader.header.alg;

    // Check that the token's algorithm is in the allowed list
    if (!allowedAlgorithms.includes(tokenAlg)) {
        throw new Error(`Algorithm "${tokenAlg}" is not allowed. Allowed: ${allowedAlgorithms.join(', ')}`);
    }

    // Verify with the provided key and algorithms
    try {
        const payload = jwt.verify(token, secretOrKey, { algorithms: allowedAlgorithms });
        return payload;
    } catch (err) {
        throw new Error(`Token verification failed: ${err.message}`);
    }
}

module.exports = verifyJWT;

// Example usage:
// const secret = 'your-strong-secret-key-here';
// try {
//     const payload = verifyJWT(token, secret, ['HS256']);
//     console.log('Valid payload:', payload);
// } catch (err) {
//     console.error('Invalid token:', err.message);
// }
