# Predictable OAuth State Token �� CSRF + Account Takeover

## Vulnerability Summary

OAuth state parameter generated using predictable values (auto-incrementing integers or timestamps). An attacker can predict the next state value and craft a malicious OAuth callback URL to hijack the victim's session.

## Attack Scenario

1. Application generates OAuth state as `Date.now()` or an incrementing counter
2. Attacker initiates OAuth flow, observes their state value
3. Attacker predicts the victim's state (next timestamp/counter)
4. Attacker crafts a phishing link: `/auth/callback?code=ATTACKER_CODE&state=PREDICTED_STATE`
5. Victim clicks the link, application binds attacker's OAuth account to victim's session
6. Attacker now has access to victim's account via the bound OAuth provider

## Impact

- **Account takeover**: Attacker gains persistent access to victim's account
- **Session fixation**: OAuth binding trusted without verifying state origin
- **Credential theft**: Indirect access to all victim's data and permissions

## Remediation

```javascript
const crypto = require('crypto');

function generateState() {
  return crypto.randomBytes(32).toString('hex'); // 256-bit state
}

// Store state with session binding and expiry
function createState(sessionId) {
  const state = generateState();
  const expires = Date.now() + 5 * 60 * 1000; // 5 min expiry
  // Store: state -> { sessionId, expires, used: false }
  return state;
}

function validateState(state, sessionId) {
  const record = getStateFromStore(state);
  if (!record) throw new Error('Invalid state');
  if (record.used) throw new Error('State already used');
  if (record.sessionId !== sessionId) throw new Error('State session mismatch');
  if (Date.now() > record.expires) throw new Error('State expired');
  markAsUsed(state);
  return true;
}
```

## Checklist

- [x] Uses crypto.randomBytes() for unpredictable state
- [x] State is at least 16 bytes (32 bytes recommended)
- [x] State bound to user session
- [x] State is single-use and expires
