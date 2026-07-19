# ECB Mode Encryption �� Data Leak via Pattern Matching

## Vulnerability Summary

AES-ECB encrypts identical plaintext blocks into identical ciphertext blocks. When encrypting structured user data (e.g., role fields like "admin" vs "user"), an attacker observing ciphertext can detect repeating patterns and infer plaintext structure without decrypting.

## Attack Scenario

1. Application stores user profiles with a role field encrypted using AES-ECB
2. All "admin" users produce the same ciphertext block for the role field
3. Attacker captures encrypted profiles and identifies the admin ciphertext pattern
4. Attacker can distinguish admin users from regular users by comparing ciphertext blocks

## Impact

- **Confidentiality breach**: Pattern analysis reveals user data structure
- **Privilege escalation vector**: Admin accounts can be identified and targeted
- **Compliance violation**: Violates data protection requirements (GDPR, HIPAA)

## Remediation

Replace AES-ECB with an authenticated encryption mode:

```javascript
const crypto = require('crypto');

function encryptAESGCM(plaintext, key) {
  const iv = crypto.randomBytes(12); // 96-bit IV for GCM
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const encrypted = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return { iv: iv.toString('hex'), encrypted: encrypted.toString('hex'), tag: tag.toString('hex') };
}

function decryptAESGCM(data, key) {
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, Buffer.from(data.iv, 'hex'));
  decipher.setAuthTag(Buffer.from(data.tag, 'hex'));
  return Buffer.concat([decipher.update(Buffer.from(data.encrypted, 'hex')), decipher.final()]).toString('utf8');
}
```

## Checklist

- [x] No ECB mode used
- [x] Authenticated encryption (AEAD) with AES-256-GCM
- [x] Initialization vector randomly generated (96-bit for GCM)
- [x] Auth tag verified on decryption
