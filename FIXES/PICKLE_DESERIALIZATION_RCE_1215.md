# Fix: Python Pickle Deserialization RCE via Cache

## Vulnerability
Redis cache stores user sessions and application data serialized with pickle.dumps(). Attackers write malicious pickle payloads to the cache. When the server calls pickle.loads(), arbitrary code execution is triggered.

## Fix Implementation
1. Replace pickle with JSON serialization for all cache data
2. Add HMAC-SHA256 signature verification for data integrity
3. Implement SafeRedisCache wrapper that never uses pickle
4. Provide PickleFreeSerializer as a drop-in replacement for existing code

## Security Properties
- **No RCE**: JSON deserialization never executes arbitrary code
- **Integrity**: HMAC signatures detect any tampering of cached data
- **Drop-in compatible**: PickleFreeSerializer has the same dumps/loads interface

## References
- CWE-502: Deserialization of Untrusted Data
- OWASP Top 10: A8:2017-Insecure Deserialization
