# Fix: WebSocket Hijacking via Missing Cookie Validation — Issue #1350

**Difficulty:** Hard · **Bounty:** $150 · **Labels:** security, bug, hard

## Vulnerability

The WebSocket upgrade validates only the `Origin` header, then trusts the
connection for its lifetime, with authentication riding on the ambient session
**cookie**. This is Cross-Site WebSocket Hijacking (CSWSH):

- `Origin` is not authentication — non-browser clients set it freely, and any
  allowlist slip (subdomain, `null`, sloppy regex) defeats it.
- The session cookie is ambient, so a victim who merely loads the attacker's
  page opens an authenticated socket **as the victim**.
- After the handshake, individual messages are never re-authenticated, so a
  hijacked/borrowed connection can impersonate the user indefinitely.

CWE-346 (Origin Validation Error), CWE-1385 (Missing Origin Validation in
WebSockets), CWE-613 (Insufficient Session Expiration).

## Fix

Implemented in [`fix_1350.py`](./fix_1350.py), mapping to the issue's acceptance
criteria:

1. **Bearer token on connection.** `SecureWebSocketServer.authenticate_connection`
   requires a non-ambient signed token (`Authorization: Bearer …`) — not the
   cookie. `Origin` is still checked as defence in depth but is never the sole
   control. Passing Origin without a token is rejected.
2. **Token on every message.** `authenticate_message` re-verifies the token's
   signature and expiry for each message; expired or revoked tokens are rejected
   mid-stream.
3. **Token bound to user session.** Tokens embed `sub` (user) + `sid` (session)
   and are checked against a live session store. A message whose token does not
   match the connection's bound user/session is rejected, so a hijacked
   transport cannot speak for another user.

`SessionTokenAuthenticator` issues/verifies HMAC-signed tokens and supports
`revoke_session()` (logout / rotation) so revocation takes effect on the next
message.

## Verification

`tests/test_websocket_hijacking_1350_fix.py` (10 tests, all pass): connection
requires a valid Bearer token (Origin alone insufficient); bad origin and forged
tokens rejected; every message re-verified; expired and revoked tokens rejected
mid-stream; and a connection cannot send messages authenticated as another user
or another session (binding).

## References

- CWE-346, CWE-1385, CWE-613
- OWASP: Testing for Cross-Site WebSocket Hijacking (WSTG-CLNT-10)
