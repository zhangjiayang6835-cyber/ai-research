// cache-fix.js - Mitigate cache poisoning via unkeyed headers
// This module provides a safe cache key generator and a middleware to sanitize headers.

const crypto = require('crypto');

/**
 * Generate a secure cache key from request-safe components.
 * Never include headers like X-Forwarded-Host, X-Forwarded-Proto, etc.
 * Use only method, path, and query string (sorted to avoid duplicate keys).
 * 
 * @param {object} req - Express request object
 * @returns {string} - SHA256 hash of the key components
 */
function generateSafeCacheKey(req) {
  const { method, path, query } = req;
  // Sort query parameters to prevent order-based duplicates
  const sortedQuery = Object.keys(query)
    .sort()
    .reduce((acc, key) => {
      acc[key] = query[key];
      return acc;
    }, {});

  const keyParts = [
    method || 'GET',
    path || '/',
    JSON.stringify(sortedQuery)
  ];

  const rawKey = keyParts.join('|');
  // Use a hash to keep key size manageable and hide internal structure
  return crypto.createHash('sha256').update(rawKey).digest('hex');
}

/**
 * Express middleware that strips unkeyed headers from req.headers
 * before caching logic runs. Prevents attackers from injecting cache keys.
 */
function sanitizeCacheHeaders(req, res, next) {
  // List of headers that should NOT influence cache keys
  const unkeyedHeaders = [
    'x-forwarded-host',
    'x-forwarded-proto',
    'x-forwarded-for',
    'x-real-ip',
    'cf-connecting-ip',
    'fastly-client-ip'
  ];

  unkeyedHeaders.forEach(header => {
    delete req.headers[header];
  });

  next();
}

module.exports = {
  generateSafeCacheKey,
  sanitizeCacheHeaders
};
