# Fix: CL.TE HTTP Request Smuggling → Cache Poisoning

## Vulnerability
Front-end nginx uses Content-Length while back-end uses Transfer-Encoding: chunked. Attackers craft ambiguous requests that cause front-end and back-end to disagree on request boundaries, poisoning the cache.

## Attack Vector
```
POST / HTTP/1.1
Content-Length: 44
Transfer-Encoding: chunked

0

GET /admin HTTP/1.1
```

## Fix Implementation
1. Reject requests with both Content-Length and Transfer-Encoding
2. Normalize Transfer-Encoding header parsing
3. Use HTTP/2 to eliminate parsing ambiguity

## References
- CWE-444: Inconsistent Interpretation of HTTP Requests
