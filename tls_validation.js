const https = require('https');
const crypto = require('crypto');

// Expected certificate fingerprint (SHA-256) for the legitimate server
const EXPECTED_FINGERPRINT = 'sha256$xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx';

/**
 * Performs an HTTPS request with TLS certificate pinning.
 * @param {string} host - The server hostname.
 * @param {number} port - The port (default 443).
 * @param {string} path - The request path.
 * @returns {Promise<Buffer>} - Response body.
 */
function httpsRequestWithPinning(host, port = 443, path = '/') {
    return new Promise((resolve, reject) => {
        const options = {
            host,
            port,
            path,
            method: 'GET',
            rejectUnauthorized: false, // Disable default CA check to use custom callback
            checkServerIdentity: (host, cert) => {
                // Compute SHA-256 fingerprint of the DER certificate
                const der = cert.raw;
                const hash = crypto.createHash('sha256').update(der).digest('hex');
                const expectedHash = EXPECTED_FINGERPRINT.split('$')[1];
                if (hash !== expectedHash) {
                    return new Error('Certificate fingerprint mismatch');
                }
                return undefined; // No error
            }
        };

        const req = https.request(options, (res) => {
            const chunks = [];
            res.on('data', chunk => chunks.push(chunk));
            res.on('end', () => {
                const body = Buffer.concat(chunks);
                resolve(body);
            });
        });

        req.on('error', (err) => {
            reject(err);
        });

        req.end();
    });
}

// Example usage (replace with actual host and fingerprint)
// httpsRequestWithPinning('example.com').then(console.log).catch(console.error);

module.exports = { httpsRequestWithPinning };
