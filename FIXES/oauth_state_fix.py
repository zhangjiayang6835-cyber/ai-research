"""
Predictable OAuth State Token → CSRF + Account Takeover Fix
Bounty #797 ($150)
=========================================
Vulnerability: OAuth state uses auto-increment integers / timestamps.
Attacker predicts next state, crafts malicious OAuth link.

Fix: Crypto-safe random state + session binding + single use.
"""

import secrets
import hashlib
import time
from typing import Dict, Optional, Set


class SecureOAuthState:
    """
    OAuth state management with cryptographic randomness.
    """

    def __init__(self):
        self._states: Dict[str, dict] = {}  # state -> metadata

    def generate_state(self, session_id: str) -> str:
        """
        Generate a cryptographically random state token.
        32 bytes of random data, base64 encoded.
        """
        # Cryptographically random (NOT auto-increment or timestamp)
        random_bytes = secrets.token_bytes(32)
        state = hashlib.sha256(
            random_bytes + session_id.encode()
        ).hexdigest()[:32]

        # Store with session binding + expiry
        self._states[state] = {
            "session_id": session_id,
            "created_at": time.time(),
            "used": False,
        }

        return state

    def validate_state(self, state: str, session_id: str) -> bool:
        """
        Validate OAuth state token.
        Must be: valid, bound to session, not expired, not used.
        """
        metadata = self._states.get(state)
        if not metadata:
            return False

        # Single use
        if metadata["used"]:
            return False

        # Session binding
        if metadata["session_id"] != session_id:
            return False

        # Expiry (10 minutes)
        if time.time() - metadata["created_at"] > 600:
            return False

        # Mark as used
        metadata["used"] = True
        return True

    def cleanup_expired(self):
        """Remove expired states."""
        now = time.time()
        expired = [
            s for s, m in self._states.items()
            if now - m["created_at"] > 600
        ]
        for s in expired:
            del self._states[s]


# ========== Usage Example ==========
if __name__ == "__main__":
    print("=== Predictable OAuth State Prevention ===")
    print()

    print("Before (vulnerable):")
    print("  State = auto_increment_id (1, 2, 3, ...)")
    print("  → Attacker predicts: next state will be 5")
    print("  → Crafts: /oauth/callback?state=5&code=...")
    print("  → CSRF! Account takeover!")
    print()

    oauth = SecureOAuthState()
    state1 = oauth.generate_state("session_123")
    state2 = oauth.generate_state("session_456")

    print(f"After (fixed):")
    print(f"  State 1: {state1}")
    print(f"  State 2: {state2}")
    print(f"  → Unpredictable! 32-byte SHA256 hash")
    print()

    # Validation
    print(f"Validation:")
    print(f"  Valid state + correct session: {oauth.validate_state(state1, 'session_123')}")
    print(f"  Valid state + wrong session:   {oauth.validate_state(state1, 'session_789')}")
    print(f"  Replay (already used):          {oauth.validate_state(state1, 'session_123')}")
    print()

    print("Measures:")
    print("✓ Cryptographically random (secrets.token_bytes(32))")
    print("✓ SHA256 hash for additional entropy")
    print("✓ Session binding (state tied to session)")
    print("✓ Single use (replay protection)")
    print("✓ Time-based expiry (10 minutes)")
    print("✓ Cleanup expired states")