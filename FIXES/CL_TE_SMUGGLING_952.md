# Fix: CL.TE HTTP Request Smuggling → Cache Poisoning

## Vulnerability
Front-end nginx uses Content-Length while back-end uses Transfer-Encoding: chunked. Attackers craft ambiguous requests causing front-end and back-end to disagree on request boundaries, poisoning the cache.

## Fix Implementation
1. Reject requests with both Content-Length and Transfer-Encoding
2. Normalize Transfer-Encoding header parsing
3. Use HTTP/2 to eliminate parsing ambiguity

## References
- CWE-444: Inconsistent Interpretation of HTTP Requests
