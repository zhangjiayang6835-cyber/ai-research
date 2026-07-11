# Fix: Server-Side Prototype Pollution to RCE

## Vulnerability

Express applications that use `lodash.merge` or similar deep-merge functions to process user-supplied JSON input are vulnerable to prototype pollution. An attacker can inject `__proto__` or `constructor.prototype` keys into the JSON payload, polluting `Object.prototype` and achieving RCE.

## Attack Vector

```javascript
// VULNERABLE: Using lodash.merge with user input
const lodash = require('lodash');
const express = require('express');
const app = express();

app.post('/api/config', (req, res) => {
    // Attacker sends: {"__proto__": {"admin": true}}
    // This pollutes Object.prototype.admin = true
    lodash.merge(app.config, req.body);
    
    // Now ALL objects have admin: true
    if (req.user.admin) {  // Always true!
        // Privilege escalation
    }
});
```

## Fix Implementation

### 1. Input Sanitization (JavaScript)

```javascript
function sanitizeInput(data) {
    if (Array.isArray(data)) {
        return data.map(sanitizeInput);
    }
    if (data !== null && typeof data === 'object') {
        // Check for pollution keys
        for (const key of Object.keys(data)) {
            if (key === '__proto__' || key === 'constructor' || key === 'prototype') {
                throw new Error(`Prototype pollution detected: ${key}`);
            }
        }
        // Recursively sanitize
        const result = {};
        for (const [key, value] of Object.entries(data)) {
            if (key !== '__proto__' && key !== 'constructor' && key !== 'prototype') {
                result[key] = sanitizeInput(value);
            }
        }
        return result;
    }
    return data;
}

// Safe deep merge (replaces lodash.merge)
function safeDeepMerge(target, source) {
    for (const key of Object.keys(source)) {
        if (key === '__proto__' || key === 'constructor' || key === 'prototype') {
            throw new Error(`Prototype pollution detected: ${key}`);
        }
        if (source[key] !== null && typeof source[key] === 'object' &&
            target[key] !== null && typeof target[key] === 'object') {
            safeDeepMerge(target[key], source[key]);
        } else {
            target[key] = source[key];
        }
    }
    return target;
}

// Usage
app.post('/api/config', (req, res) => {
    const safeData = sanitizeInput(req.body);
    safeDeepMerge(app.config, safeData);
    // Safe from prototype pollution
});
```

### 2. Security Checklist

- [x] Strip `__proto__` keys from user input
- [x] Strip `constructor.prototype` keys
- [x] Recursive validation of all nested objects
- [x] Safe deep-merge function (replaces lodash.merge)
- [x] Reject all prototype pollution vectors

## References

- CVE-2019-10744: lodash prototype pollution
- Snyk: Prototype Pollution in lodash
- OWASP: Prototype Pollution Prevention Cheat Sheet

## Wallet for Bounty Payment
- **ETH/EVM (Ethereum, Polygon, Base, Optimism, Arbitrum):** `0x415b24ab21388dbfb9c4da97cb1ab2b53ff21e29`
- **SOL (Solana):** `J6pwNJNbjYx7UHAvZK369kYRJHim8JVbeFEHRSqtFMjv`