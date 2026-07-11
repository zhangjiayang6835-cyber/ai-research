# Issue #674 — Host Header Injection → Password Reset Poisoning

**Bounty**: $120 | **Difficulty**: Easy

## Vulnerability

The password reset endpoint constructs the reset link using the
inbound `Host` header:

```python
reset_url = f"https://{request.host}/reset?token={token}"
```

An attacker sends `Host: evil.example.com` and the victim receives a
phishing link instead of the legitimate reset URL.

## Fix

See `fixes/host_header_injection_674.py`.

The fix provides:

1. **Trusted-host allow-list** — configured at startup, never inferred
   from the request.
2. **Strict validation** — case-insensitive, port-aware comparison;
   rejects CRLF, duplicates, embedded credentials, non-ASCII, path
   smuggling.
3. **`build_reset_url()` helper** — the only place application code
   should call to construct a reset link.

## Acceptance Criteria

- [x] Configure trusted Host list
- [x] Validate Host header against whitelist
- [x] Build all links with absolute URL + trusted domain

## Migration

Replace:

```python
url = f"https://{request.host}/reset?token={token}"
```

With:

```python
from fixes.host_header_injection_674 import (
    HostPolicy, build_reset_url, HostValidationError,
)

policy = HostPolicy.from_iterable(["app.example.com"])

try:
    url = build_reset_url(request.headers, policy, token)
except HostValidationError as e:
    return {"error": "bad request"}, 400
```
