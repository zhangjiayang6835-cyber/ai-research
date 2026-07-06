const jwt = require('jsonwebtoken');

// Strong secret (must be at least 32 bytes random)
const SECRET_KEY = 'your-very-strong-secret-key-at-least-32-characters-long';

function verifyJwt(token) {
    try {
        // Decode without verification to check algorithm
        const decoded = jwt.decode(token, { complete: true });
        if (!decoded) {
            throw new Error('Invalid token');
        }
        const { header } = decoded;
        // Check for None algorithm
        if (!header.alg || header.alg === 'None' || header.alg === 'none') {
            throw new Error('Algorithm None is not allowed');
        }
        // Verify token with strong secret and algorithm whitelist
        const payload = jwt.verify(token, SECRET_KEY, {
            algorithms: ['HS256'],
            // Additional options: ignoreExpiration? depends on need
        });
        // Validate kid if present
        if (payload.kid) {
            const allowedKids = ['key1', 'key2'];
            if (!allowedKids.includes(payload.kid)) {
                throw new Error('Invalid kid');
            }
        }
        return payload;
    } catch (error) {
        throw new Error(`JWT verification failed: ${error.message}`);
    }
}

module.exports = { verifyJwt };
