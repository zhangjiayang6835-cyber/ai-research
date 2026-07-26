#!/usr/bin/env python3
"""
Fix for Issue #1476: Predictable OAuth State Token → CSRF + Account Takeover

Vulnerability: OAuth state parameter uses auto-increment integers or timestamps,
allowing attackers to predict the next state and craft malicious OAuth links.

Fix: Use crypto.randomBytes() for unpredictable state tokens, bind state to
user session, enforce single-use with TTL.
"""

import secrets, hashlib, hmac, time
from typing import Dict, Optional, Tuple
from dataclasses import dataclass, field

@dataclass
class OAuthState:
    token: str          # Unpredictable random token (32 bytes hex)
    session_id: str     # Bound to user's session
    created_at: float = field(default_factory=time.time)
    used: bool = False
    redirect_uri: str = ''

class SecureOAuthStateManager:
    """Manages OAuth state tokens with cryptographic security."""

    STATE_TTL = 600  # 10 minutes max

    def __init__(self):
        self._states: Dict[str, OAuthState] = {}

    def generate_state(
        self, session_id: str, redirect_uri: str = ''
    ) -> str:
        """
        Generate unpredictable OAuth state token.

        Uses secrets.token_hex (cryptographically secure random):
        - 32 random bytes → 64 hex chars (256 bits entropy)
        - Bound to session_id (prevents cross-session reuse)
        - Bound to redirect_uri (prevents redirect manipulation)
        - Single-use with TTL
        """
        token = secrets.token_hex(32)
        state = OAuthState(
            token=token,
            session_id=session_id,
            redirect_uri=redirect_uri,
        )
        # Cleanup expired states
        now = time.time()
        self._states = {k: v for k, v in self._states.items()
                       if now - v.created_at < self.STATE_TTL}

        # Store for verification
        self._states[token] = state
        return token

    def verify_state(
        self, state_token: str, session_id: str, redirect_uri: str = ''
    ) -> bool:
        """
        Verify OAuth state token:
        1. Token exists and not expired
        2. Token not already used (single-use)
        3. Token bound to correct session
        4. Token bound to correct redirect URI
        """
        state = self._states.get(state_token)
        if not state:
            print("[SEC] State token not found or expired")
            return False

        now = time.time()
        if now - state.created_at > self.STATE_TTL:
            self._states.pop(state_token, None)
            print("[SEC] State token expired")
            return False

        if state.used:
            print("[SEC] State token already used (replay attack)")
            return False

        # Constant-time comparison for session binding
        if not hmac.compare_digest(state.session_id, session_id):
            print("[SEC] State token session mismatch")
            return False

        # Verify redirect URI (optional but recommended)
        if state.redirect_uri and redirect_uri:
            if state.redirect_uri != redirect_uri:
                print("[SEC] State token redirect URI mismatch")
                return False

        # Mark as used (prevents replay)
        state.used = True
        return True

# --- VULNERABLE (DO NOT USE) ---
class InsecureOAuthStateManager:
    """⚠️ Uses predictable auto-increment counter for state token."""
    def __init__(self):
        self._counter = 0
    def generate_state(self) -> str:
        self._counter += 1
        # PREDICTABLE: just the counter as string!
        return str(self._counter)
    def verify_state(self, token: str) -> bool:
        return bool(token)  # Always returns True!

if __name__ == '__main__':
    mgr = SecureOAuthStateManager()

    # Test: generate unpredictable state
    s1 = mgr.generate_state('session_abc', 'https://app.example.com/callback')
    s2 = mgr.generate_state('session_abc', 'https://app.example.com/callback')
    assert s1 != s2, "States should be different!"
    assert len(s1) == 64, f"State should be 64 hex chars, got {len(s1)}"
    print(f"✅ State tokens: {s1[:16]}... != {s2[:16]}... (unpredictable)")

    # Test: verify with correct session
    assert mgr.verify_state(s1, 'session_abc', 'https://app.example.com/callback')
    print("✅ Correct session + redirect → verified")

    # Test: single-use (cannot reuse)
    assert not mgr.verify_state(s1, 'session_abc')
    print("✅ Replay blocked (single-use)")

    # Test: wrong session rejected
    token = mgr.generate_state('session_xyz')
    assert not mgr.verify_state(token, 'session_hacker')
    print("✅ Cross-session blocked")

    # Test: stale state cleaned up
    old = OAuthState(token='expired', session_id='old_session',
                     created_at=time.time() - 3600)
    mgr._states['expired'] = old
    mgr.generate_state('new_session')  # Cleanup triggers
    assert 'expired' not in mgr._states
    print("✅ Expired state cleaned up")

    # Demonstrate the vulnerability
    insecure = InsecureOAuthStateManager()
    pred1 = insecure.generate_state()
    pred2 = insecure.generate_state()
    print(f"\n⚠️  Insecure states: {pred1}, {pred2} (predictable!)")

    print("\n🔒 Issue #1476 FIXED: unpredictable state + session binding + single-use")
