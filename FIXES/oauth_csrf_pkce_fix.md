# Fix: OAuth 2.0 CSRF → Account Takeover via State Bypass (#664)

## Vulnerability

The OAuth callback endpoint does not validate the `state` parameter. An attacker can craft a malicious OAuth authorization URL that, when followed by a victim, binds the attacker's account to the victim's application account — full account takeover.

### Attack Flow
1. Attacker constructs OAuth URL with their own `client_id` and `redirect_uri` pointing to attacker-controlled domain
2. Victim (authenticated in app) clicks the link
3. OAuth provider redirects to attacker's domain with authorization code
4. Attacker exchanges code for tokens, gaining access to victim's account

### Root Causes
- No `state` parameter generated or validated during OAuth flow
- Callback handler trusts any `code` and `state` from provider without verification
- No PKCE (RFC 7636) used, so intercepted codes can be exchanged
- Implicit Grant flow (`response_type=token`) allows token leakage

## Fix

- **State parameter**: Cryptographically random state bound to user session
- **PKCE (S256)**: Mandatory proof key for code exchange — prevents code interception
- **Authorization Code Flow only**: Implicit/Hybrid flows banned per OAuth 2.1
- **Redirect URI exact match**: No wildcards, no path prefix matching
- **One-time state**: States are consumed on validation, preventing replay
- **Session binding**: State tied to session ID, preventing cross-session attacks

## Implementation

- `FIXES/oauth_csrf_pkce_fix.py` — Drop-in `SecureOAuthHandler` class
- `StateManager` — Generate/validate cryptographically random states with TTL
- `verify_pkce()` — Constant-time S256 verifier check
- `validate_redirect_uri()` — Exact-match redirect URI validation
- `reject_implicit_flow()` — Explicit ban on `response_type=token`

## Verification Checklist

- [x] State parameter generated and validated on every OAuth request
- [x] State bound to user session ID
- [x] PKCE S256 enforced for all authorization requests
- [x] Redirect URI exact-match validation
- [x] Implicit Grant flow explicitly rejected
- [x] Authorization codes are single-use
- [x] Self-tests verify all attack vectors are blocked

## References

- [RFC 6749 §4.1.1](https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.1) — OAuth 2.0 Authorization Code Flow
- [RFC 7636](https://datatracker.ietf.org/doc/html/rfc7636) — PKCE
- [RFC 9700](https://datatracker.ietf.org/doc/html/rfc9700) — OAuth 2.0 Security Best Current Practice
- [OWASP OAuth 2.0 Threat Model](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Session_Management_Testing/04-Testing_for_OAuth_Authentication_Credentials_Manipulation)
