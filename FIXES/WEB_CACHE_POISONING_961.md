# Fix: Web Cache Poisoning via Unkeyed Header

## Vulnerability
CDN/reverse proxy treats X-Forwarded-Host as part of the cache key but does not include it in the cache key calculation. Attackers set a malicious X-Forwarded-Host to make the CDN cache a page containing malicious JS, distributed to all users.

## Fix Implementation
1. Include all headers affecting the response in the cache key
2. Normalize the Vary response header
3. Disable non-standard headers from origin

## References
- CWE-524: Use of Cache Containing Sensitive Information
