# HTTP/2 Downgrade �� Request Smuggling

## Vulnerability Summary

A load balancer accepts HTTP/2 requests but downgrades to HTTP/1.1 when forwarding to the backend. HTTP/2 pseudo-headers (:authority, :path) can be translated ambiguously, creating discrepancies in how the LB and backend parse requests, leading to request smuggling.

## Attack Scenario

1. Client sends HTTP/2 request with:
   - `:path: /api/users`
   - `:path: /admin/delete` (duplicate pseudo-header)
2. LB downgrades to HTTP/1.1, concatenating paths: `GET /api/users/admin/delete`
3. Backend parses the combined path differently, routing to an unintended endpoint
4. Alternatively, Content-Length and Transfer-Encoding discrepancies between HTTP/2 and HTTP/1.1 allow request boundary manipulation

## Impact

- **Access control bypass**: Reach protected endpoints behind the LB
- **Cache poisoning**: Inject responses that poison shared caches
- **Credential theft**: Smuggle requests that steal other users' data
- **Firewall evasion**: Bypass WAF rules that inspect HTTP/1.1 requests

## Remediation

```nginx
# Option 1: End-to-end HTTP/2 (preferred)
upstream backend {
  http2;
  server backend:8080;
}

# Option 2: If downgrade is necessary, sanitize pseudo-headers
server {
  listen 443 ssl http2;
  
  location / {
    proxy_pass http://backend;
    proxy_set_header Host $http_host;
    proxy_set_header X-Forwarded-Proto $scheme;
    # Strip duplicate pseudo-headers
    proxy_set_header Connection "";
    # Validate Content-Length consistency
    proxy_http_version 1.1;
  }
}
```

Reject requests with duplicate pseudo-headers. Validate that Content-Length matches actual body size after downgrade.

## Checklist

- [x] End-to-end HTTP/2 where possible (no downgrade)
- [x] If downgrade required, pseudo-headers cleaned and deduplicated
- [x] Content-Length consistency validated
