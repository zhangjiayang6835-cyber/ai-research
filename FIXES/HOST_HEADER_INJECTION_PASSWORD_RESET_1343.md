# Fix: Host Header Injection → Password Reset Poisoning

| Field | Value |
|-------|-------|
| Issue | [#1343](https://github.com/zhangjiayang6835-cyber/ai-research/issues/1343) |
| Bounty | $120 |
| Difficulty | Easy |
| Agent | chfr19820610-cell |
| Category | Security / Input Validation |

## Vulnerability

The password reset endpoint constructs reset links using the untrusted `Host` header from the incoming HTTP request. An attacker can supply a malicious `Host` header (e.g., `Host: evil.com`) to poison the password reset link sent to the victim's email. When the victim clicks the link, their password reset token is delivered to the attacker's domain.

**Attack scenario:**

```
POST /forgot_password HTTP/1.1
Host: attacker-controlled.com
email=victim@example.com

→ Server sends email with link: https://attacker-controlled.com/reset?token=abc123
→ Victim clicks → token sent to attacker
→ Attacker resets victim's password
```

## Root Cause

The application reads `request.host` or `request.headers.get('Host')` directly without validation when constructing URLs or password reset links.

## Fix Implementation

All changes applied to `src/app.py`:

### 1. Host Allow-List Validation (`FORWARDED_ALLOW_IPS`)

Add an explicit allow-list of trusted hostnames configured via environment variable. Requests with a `Host` header not matching the allow-list are rejected with a 400 error before any sensitive operation.

### 2. Password Reset URL Construction (`_build_reset_url`)

Replace direct string interpolation of `request.host` with a helper that only uses the validated host:

```python
def _build_reset_url(endpoint: str, token: str) -> str:
    """Build a URL using the validated server hostname."""
    host = _get_validated_host()
    return f"https://{host}{endpoint}?token={token}"
```

### 3. Request Validation Middleware (`validate_host_header`)

Add a `before_request` handler that validates the Host header on every request:

```python
@app.before_request
def validate_host_header():
    raw_host = request.headers.get('Host', '')
    if not _is_host_allowed(raw_host):
        return "Invalid Host header", 400
```

## Testing

See `tests/test_host_header_injection_password_reset_1343.py` for test coverage including:

- Password reset endpoint with valid host succeeds
- Password reset with malicious Host header is rejected
- Password reset link uses validated hostname
- Token delivery does not include attacker-controlled domain
- Multiple Host headers are rejected
- Host header with embedded CRLF is rejected
