# Fix: Python Pickle Deserialization RCE via Cache

## Vulnerability
Redis cache stores user sessions serialized with pickle.dumps(). Attackers write malicious pickle payloads to the cache. When the server calls pickle.loads(), arbitrary code execution is triggered.

## Fix Implementation
1. Replace pickle with JSON serialization
2. If pickle must be used, add HMAC signature verification
3. Sign cached data to prevent tampering

## References
- CWE-502: Deserialization of Untrusted Data
