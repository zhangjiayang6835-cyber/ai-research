# Fix: Web Cache Deception → Session Token Leak

## Vulnerability
Static file CDN is configured to cache /assets/*.css. Attacker tricks victim into visiting /account/settings/nonexistent.css. CDN caches the page containing sensitive info (due to .css suffix), and attacker reads the cache to steal session tokens.

## Fix Implementation
1. Cache rules based on Content-Type, not file extension
2. Sensitive pages return Cache-Control: no-store
3. Configure CDN to not cache authenticated pages

## References
- CWE-524: Use of Cache Containing Sensitive Information
