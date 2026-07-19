# JWT Kid Injection to Path Traversal

## Description
JWT verification uses the kid header to locate the signing key file. Attacker manipulates kid to traverse paths and use arbitrary files as the HMAC key. Using /dev/null results in an empty key that the attacker can forge.

## Impact
Authentication bypass, arbitrary file read, token forgery for any user.

## Remediation
Validate kid against whitelist of key IDs, never use file paths from JWT headers, use key rotation with fixed identifiers.