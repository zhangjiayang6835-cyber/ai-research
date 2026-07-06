#!/usr/bin/env node
'use strict';

/**
 * Secure session cookie encryption using AES-256-GCM (Node.js crypto).
 * This prevents padding oracle attacks by ensuring integrity and authenticity.
 */

const crypto = require('crypto');

const ALGORITHM = 'aes-256-gcm';
const IV_LENGTH = 12;  // 96-bit nonce
const TAG_LENGTH = 16; // 128-bit authentication tag

/**
 * Encrypt and authenticate data.
 * @param {Buffer} data - Data to encrypt.
 * @param {Buffer} key - 32-byte key.
 * @returns {string} Base64-encoded nonce + ciphertext + tag.
 */
function encryptCookie(data, key) {
    if (key.length !== 32) {
        throw new Error('Key must be 32 bytes');
    }
    const iv = crypto.randomBytes(IV_LENGTH);
    const cipher = crypto.createCipheriv(ALGORITHM, key, iv, { authTagLength: TAG_LENGTH });
    let encrypted = cipher.update(data);
    encrypted = Buffer.concat([encrypted, cipher.final()]);
    const tag = cipher.getAuthTag();
    // Combine: iv + encrypted + tag
    const combined = Buffer.concat([iv, encrypted, tag]);
    return combined.toString('base64');
}

/**
 * Decrypt and verify authentication.
 * @param {string} encrypted - Base64-encoded ciphertext.
 * @param {Buffer} key - 32-byte key.
 * @returns {Buffer} Decrypted data.
 * @throws {Error} If authentication fails or format invalid.
 */
function decryptCookie(encrypted, key) {
    if (key.length !== 32) {
        throw new Error('Key must be 32 bytes');
    }
    const combined = Buffer.from(encrypted, 'base64');
    if (combined.length < IV_LENGTH + TAG_LENGTH) {
        throw new Error('Invalid ciphertext length');
    }
    const iv = combined.slice(0, IV_LENGTH);
    const tag = combined.slice(-TAG_LENGTH);
    const ciphertext = combined.slice(IV_LENGTH, -TAG_LENGTH);
    const decipher = crypto.createDecipheriv(ALGORITHM, key, iv, { authTagLength: TAG_LENGTH });
    decipher.setAuthTag(tag);
    try {
        let decrypted = decipher.update(ciphertext);
        decrypted = Buffer.concat([decrypted, decipher.final()]);
        return decrypted;
    } catch (err) {
        // In production, log error and do not reveal padding details
        throw new Error('Decryption failed: cookie may be tampered');
    }
}

// Example usage (for testing) - do not hardcode keys in production
if (require.main === module) {
    const key = crypto.randomBytes(32);
    const cookieData = Buffer.from(JSON.stringify({ user: 'admin', role: 'user' }));
    const enc = encryptCookie(cookieData, key);
    console.log('Encrypted cookie:', enc);
    const dec = decryptCookie(enc, key);
    console.log('Decrypted:', dec.toString('utf8'));
    // Attempt tampering (should fail)
    try {
        const tampered = enc.slice(0, -1) + (enc.slice(-1) === 'a' ? 'b' : 'a');
        decryptCookie(tampered, key);
    } catch (e) {
        console.log('Tampered cookie detected:', e.message);
    }
}

module.exports = { encryptCookie, decryptCookie };
