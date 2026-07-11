# Fix: Host Header Injection → Password Reset Poisoning (Issue #963)

**Bounty**: $120 | **Difficulty**: Easy

## Vulnerability

Password reset links are generated using the request's `Host` header:
`https://{Host}/reset?token=***`

An attacker sends `Host: attacker.com`, and the victim receives a reset link
pointing to the phishing site. When the victim clicks the link and enters
their new password, the attacker captures it.

## Root Cause

The application uses the client-supplied Host header to construct absolute
URLs without validation.

## Fix Strategy

1. Define a trusted host allow-list (`TRUSTED_HOSTS`) in configuration.
2. Add a `@app.before_request` hook to reject requests whose Host header is
   not in the whitelist.
3. Add `get_safe_base_url()` helper that never uses the user-supplied Host
   header for URL generation — always validates against the whitelist.
4. Add `/password_reset` endpoint that uses `get_safe_base_url()` exclusively.
5. Add security headers (`X-Content-Type-Options`, `X-Frame-Options`,
   `X-XSS-Protection`) via `@app.after_request`.

## Files Changed

- `src/app.py` — Added `TRUSTED_HOSTS`, `get_safe_base_url()`,
  `validate_host_header()`, `security_headers()`, and `/password_reset`
  route.

## Acceptance Criteria

- [x] Trusted host list configured in settings
- [x] Host header validated against whitelist
- [x] All reset links use absolute URL + trusted domain
- [x] Requests with untrusted Host header rejected with 400
- [x] Security headers set on all responses

## References

- OWASP: Host Header Injection
- CWE-644: Improper Neutralization of HTTP Headers for Scripting Syntax