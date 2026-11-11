# Fix: CORS Misconfiguration + Origin Reflection → Credential Theft (Issue #955)

**Bounty**: $120 | **Difficulty**: Easy

## Vulnerability

The API response headers directly reflect the request's Origin value:
```
Access-Control-Allow-Origin: {Origin}
Access-Control-Allow-Credentials: true
```

This allows any website to make authenticated cross-origin requests and read
the API response, leading to credential theft.

## Root Cause

The application echoes the Origin header back without validation, and enables
credentials (`Access-Control-Allow-Credentials: true`) with a dynamic origin.

## Fix Strategy

1. Implement an Origin whitelist for CORS in `src/security/cors.py`.
2. Never use wildcard (`*`) with credentials.
3. Return `Vary: Origin` header for proper cache behavior.
4. Validate the Origin against the whitelist before reflecting it.
5. Reject requests with invalid origins (no CORS headers returned).
6. Provide `init_cors(app)` function for easy Flask integration.

## Files Changed

- `src/security/cors.py` — New module with CORS protection logic:
  - `ALLOWED_ORIGINS` whitelist (configurable via `CORS_ALLOWED_ORIGINS` env)
  - `build_cors_headers()` — builds safe CORS response headers
  - `apply_cors_headers()` — applies CORS headers to Flask responses
  - `init_cors()` — registers `after_request` handler for Flask apps
  - Self-tests included (run with `python src/security/cors.py`)

## Acceptance Criteria

- [x] Origin whitelist implemented
- [x] No wildcard + credentials combination allowed
- [x] Vary: Origin header returned
- [x] CORS preflight (OPTIONS) handled correctly
- [x] Only whitelisted origins allowed with credentials
- [x] Invalid origins rejected (no CORS headers)

## References

- OWASP: CORS Misconfiguration
- CWE-942: Permissive Cross-domain Policy with Untrusted Domains
- MDN: Access-Control-Allow-Origin