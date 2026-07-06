const jwt = require('jsonwebtoken');

// Whitelist of allowed algorithms
const ALLOWED_ALGORITHMS = ['HS256', 'RS256'];

/**
 * Securely verify a JWT token.
 * @param {string} token - The JWT token.
 * @param {string|Buffer} secret - Secret for HS256.
 * @param {string} [publicKey] - Public key for RS256.
 * @returns {object} Decoded payload.
 */
function verifyJwtToken(token, secret, publicKey) {
    // Get unverified header
    const decodedHeader = jwt.decode(token, { complete: true }).header;
    const alg = decodedHeader.alg;

    if (!ALLOWED_ALGORITHMS.includes(alg)) {
        throw new Error(`Algorithm '${alg}' is not allowed.`);
    }

    // Choose key based on algorithm
    let key;
    if (alg === 'HS256') {
        key = secret;
    } else if (alg === 'RS256') {
        if (!publicKey) {
            throw new Error('Public key is required for RS256 algorithm.');
        }
        key = publicKey;
    } else {
        throw new Error(`Algorithm '${alg}' is not supported.`);
    }

    // Verify token
    const payload = jwt.verify(token, key, { algorithms: [alg] });
    return payload;
}

module.exports = verifyJwtToken;

// Example usage:
// const secret = 'my-secret';
// const publicKey = fs.readFileSync('public.pem', 'utf8');
// const token = '...';
// try {
//     const claims = verifyJwtToken(token, secret, publicKey);
// } catch (e) {
//     console.error(e.message);
// }
