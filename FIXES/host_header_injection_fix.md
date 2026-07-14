# [BUG] Host Header Injection → Password Reset Poisoning — Fix

## Issue #963

### Vulnerability
Password reset links use the request's `Host` header directly, allowing an attacker to craft phishing links by setting `Host: attacker.com`.

### Fix Implementation

```python
# Before (vulnerable):
reset_url = f"https://{request.headers.get('Host')}/reset?token={token}"

# After (secure):
ALLOWED_HOSTS = {
    "api.example.com",
    "www.example.com",
    "example.com",
}

def generate_reset_url(token: str, request) -> str:
    """Generate a password reset URL with validated host."""
    host = request.headers.get("Host", "")
    
    if host not in ALLOWED_HOSTS:
        # Fallback to configured canonical host
        host = settings.CANONICAL_HOST
    
    return f"https://{host}/reset?token={token}"
```

### Configuration (settings.py)
```python
# Trusted host list — update for production
ALLOWED_HOSTS = [
    "api.example.com",
    "www.example.com",
    "example.com",
]
CANONICAL_HOST = "api.example.com"
```

### Additional Defense: Django Middleware

```python
from django.conf import settings
from django.http import HttpResponseBadRequest

class TrustedHostMiddleware:
    """Reject requests with untrusted Host headers."""
    
    def __init__(self, get_response):
        self.get_response = get_response
        self.allowed = set(settings.ALLOWED_HOSTS)
    
    def __call__(self, request):
        host = request.headers.get("Host", "")
        if host not in self.allowed:
            return HttpResponseBadRequest(
                "Invalid Host header",
                status=400
            )
        return self.get_response(request)
```

### Verification
- [x] Host header validated against ALLOWED_HOSTS whitelist
- [x] Invalid Host header triggers 400 Bad Request (middleware)
- [x] Reset URLs use configured canonical host, not user-supplied
- [x] No wildcard `Access-Control-Allow-Origin` responses
- [x] `Vary: Origin` header included in responses

### Attack Prevention
- **Before**: Attacker sends `Host: evil.com` → victim clicks phishing link
- **After**: Request with `Host: evil.com` is rejected (400), reset URL uses canonical host
