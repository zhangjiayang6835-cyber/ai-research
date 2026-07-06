const https = require('https');
const crypto = require('crypto');
const fs = require('fs');

// Expected public key pin (base64-encoded SHA-256 hash of the SPKI)
const EXPECTED_PIN = 'YOUR_EXPECTED_PIN_BASE64';

/**
 * Makes an HTTPS request with certificate pinning to prevent BGP hijacking
 * and TLS certificate bypass.
 * @param {string} hostname - The hostname to connect to.
 * @param {number} port - The port (default 443).
 */
function secureRequest(hostname, port = 443) {
    return new Promise((resolve, reject) => {
        const req = https.request(
            {
                hostname,
                port,
                method: 'GET',
                path: '/',
                // Reject unauthorized certificates (default is true, but explicit)
                rejectUnauthorized: true,
                // Custom checkServerIdentity to enforce pinning
                checkServerIdentity: (host, cert) => {
                    // Compute SHA-256 of the raw DER public key (SPKI)
                    const pubKeyDer = cert.pubkey;
                    if (!pubKeyDer) {
                        return new Error('No public key in certificate');
                    }
                    const hash = crypto.createHash('sha256').update(pubKeyDer).digest('base64');
                    if (hash !== EXPECTED_PIN) {
                        return new Error('Certificate pin mismatch - possible hijack');
                    }
                    // Also perform default hostname check
                    return https.checkServerIdentity(host, cert);
                }
            },
            (res) => {
                let data = '';
                res.on('data', chunk => data += chunk);
                res.on('end', () => resolve(data));
            }
        );
        req.on('error', reject);
        req.end();
    });
}

// Example usage
(async () => {
    try {
        const response = await secureRequest('example.com');
        console.log('Response received:', response);
    } catch (err) {
        console.error('Secure request failed:', err.message);
    }
})();
