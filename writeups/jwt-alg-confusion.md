# JWT Algorithm Confusion RS256 to HS256

## Description
Server accepts both RS256 and HS256 algorithms. Attacker obtains the public RSA key, downgrades algorithm to HS256, and signs the token using the public key as the HMAC secret. Server verifies with HS256 using the same public key.

## Impact
Authentication bypass, token forgery for any user, privilege escalation.

## Remediation
Hardcode expected algorithm (RS256 only), never mix symmetric and asymmetric algorithms, use library that enforces algorithm selection.