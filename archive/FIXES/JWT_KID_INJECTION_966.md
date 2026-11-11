# Fix: JWT Kid Injection → Path Traversal → Secret Key Leak

## Vulnerability
JWT verification uses kid (Key ID) to load keys from filesystem: fs.readFileSync("/keys/" + decoded.kid). Attacker sets kid: ../../etc/passwd to bypass signature verification.

## Fix Implementation
1. Use kid whitelist enumeration instead of file path lookup
2. Normalize/validate kid input
3. Block path traversal characters

## References
- CWE-73: External Control of File Name or Path
- CWE-22: Path Traversal
