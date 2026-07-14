# Fix: OAuth 2.0 CSRF → Account Takeover via State Bypass

## Vulnerability
OAuth callback endpoint does not validate the state parameter. An attacker crafts a malicious OAuth link, and when the victim clicks it, the attacker's GitHub account gets bound to the victim's account.

## Fix Implementation
1. Implement state parameter with nonce validation
2. Bind state to user session
3. Enable PKCE extension

## References
- CWE-352: Cross-Site Request Forgery
- OAuth 2.0 Threat Model
