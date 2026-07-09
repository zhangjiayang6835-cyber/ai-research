"""
Fix for [BUG] WebSocket CSRF -> Cross-Origin Data Exfiltration.

Root cause
----------
The WebSocket endpoint `/ws/realtime` performed no `Origin` header validation
and no CSRF-equivalent handshake before upgrading the connection. Because the
WebSocket handshake is a plain HTTP request, browsers will happily send it
cross-origin *with* the victim's cookies attached. Without server-side
validation, an attacker-controlled page can do:

    const ws = new WebSocket('wss://target/ws/realtime');

and the browser will include the victim's session cookies, letting the
attacker's page receive the real-time data stream meant only for the
victim's own origin ("Cross-Site WebSocket Hijacking").

Fix
----
This module implements defense in depth for the WebSocket upgrade path:

  1. **Origin allowlist validation** - the `Origin` header must be present and
     match an exact-string entry in a server-configured allowlist. Missing,
     malformed, or unrecognized origins are rejected with HTTP 403 *before*
     the connection is upgraded.
  2. **CSRF challenge-response handshake** - the server issues a single-use,
     time-limited, HMAC-signed challenge token bound to the session
     (`GET /ws/realtime/csrf-challenge`, or equivalent). The client must
     present the correct HMAC-derived response value for that challenge
     (via header `X-WS-CSRF-Response`) when initiating the WebSocket
     handshake. This is a second, independent barrier: even if a proxy or
     CDN strips/rewrites Origin, the attacker still cannot compute the
     response without the server-only secret.

Every invalid handshake attempt (bad Origin OR bad/missing/expired/replayed
CSRF response) is rejected with **HTTP 403** and never reaches the upgrade
logic.

Drop-in usage:

    security = WebSocketOriginCSRFGuard(
        allowed_origins={"https://app.example.com"},
        secret=os.environ["WS_CSRF_SECRET"],
    )

    # 1. Client first requests a challenge (authenticated, same-origin call):
    challenge = security.issue_challenge(session_id="sess-123")

    # 2. Client computes response and includes it + Origin header when
    #    opening the WebSocket connection. The handshake handler calls:
    decision = security.authorize_handshake(
        origin=request.headers.get("Origin"),
        session_id="sess-123",
        challenge=challenge_id_from_client,
        response=response_from_client,
    )
    if not decision.allowed:
        return HTTPResponse(status=403, body=decision.reason)
    # else proceed to upgrade the connection to a WebSocket.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import secrets
import time
from dataclasses import dataclass, field
from typing import Dict, FrozenSet, Optional

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

CHALLENGE_TTL_SECONDS = 60          # short-lived, single-use challenge
CHALLENGE_BYTES = 32                # 256-bit challenge nonce
HTTP_FORBIDDEN = 403


# ---------------------------------------------------------------------------
# Result type
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class HandshakeDecision:
    allowed: bool
    status_code: int
    reason: str


@dataclass
class _ChallengeRecord:
    session_id: str
    expires_at: float
    used: bool = False


# ---------------------------------------------------------------------------
# Origin validation
# ---------------------------------------------------------------------------

def validate_origin(origin: Optional[str], allowed_origins: FrozenSet[str]) -> bool:
    """Return True only if `origin` is present and an exact match in the
    allowlist. No substring, suffix, prefix, wildcard, or scheme-relaxed
    matching is performed - those are common CORS/Origin-check bypasses.
    """
    if not origin:
        return False
    # Reject header injection / multi-value smuggling attempts outright.
    if "\r" in origin or "\n" in origin:
        return False
    return origin in allowed_origins


# ---------------------------------------------------------------------------
# CSRF challenge-response
# ---------------------------------------------------------------------------

class WebSocketOriginCSRFGuard:
    """Server-side guard combining Origin allowlisting with a CSRF
    challenge-response handshake for WebSocket upgrade requests.
    """

    def __init__(
        self,
        allowed_origins: set,
        secret: str,
        ttl_seconds: int = CHALLENGE_TTL_SECONDS,
        clock: callable = time.time,
    ) -> None:
        if not secret:
            raise ValueError("a non-empty server secret is required")
        self._allowed_origins: FrozenSet[str] = frozenset(allowed_origins)
        self._secret = secret.encode("utf-8")
        self._ttl_seconds = ttl_seconds
        self._clock = clock
        self._challenges: Dict[str, _ChallengeRecord] = {}

    # ---- Step 1: issue a challenge (must be requested same-origin, while
    #      the caller is already authenticated) ---------------------------

    def issue_challenge(self, session_id: str) -> str:
        """Mint a single-use challenge id bound to `session_id`."""
        challenge_id = secrets.token_urlsafe(CHALLENGE_BYTES)
        self._challenges[challenge_id] = _ChallengeRecord(
            session_id=session_id,
            expires_at=self._clock() + self._ttl_seconds,
        )
        return challenge_id

    def compute_expected_response(self, challenge_id: str, session_id: str) -> str:
        """Deterministically derive the expected response value for a given
        challenge id + session, using the server-only secret. Never sent to
        the client directly - the client must independently know its own
        session and be told the challenge id, then this function (mirrored
        client-side via a same-origin API call) yields the response value.
        """
        mac = hmac.new(
            self._secret,
            f"{challenge_id}:{session_id}".encode("utf-8"),
            hashlib.sha256,
        )
        return mac.hexdigest()

    # ---- Step 2: validate the WebSocket upgrade request -------------------

    def authorize_handshake(
        self,
        *,
        origin: Optional[str],
        session_id: str,
        challenge: Optional[str],
        response: Optional[str],
    ) -> HandshakeDecision:
        """Validate an incoming WebSocket handshake request.

        Returns a `HandshakeDecision`. Callers MUST return
        `decision.status_code` (403) and refuse the upgrade whenever
        `decision.allowed` is False.
        """
        # 1. Origin allowlist check - first line of defense.
        if not validate_origin(origin, self._allowed_origins):
            return HandshakeDecision(
                allowed=False,
                status_code=HTTP_FORBIDDEN,
                reason="origin_not_allowed",
            )

        # 2. CSRF challenge-response check - second, independent barrier.
        if not challenge or not response or not session_id:
            return HandshakeDecision(
                allowed=False,
                status_code=HTTP_FORBIDDEN,
                reason="missing_csrf_challenge",
            )

        record = self._challenges.get(challenge)
        if record is None:
            return HandshakeDecision(
                allowed=False,
                status_code=HTTP_FORBIDDEN,
                reason="unknown_or_consumed_challenge",
            )

        # Single-use: burn the challenge regardless of outcome to prevent
        # brute-force / replay of a captured response value.
        if record.used:
            self._challenges.pop(challenge, None)
            return HandshakeDecision(
                allowed=False,
                status_code=HTTP_FORBIDDEN,
                reason="challenge_already_used",
            )
        record.used = True

        try:
            if self._clock() > record.expires_at:
                return HandshakeDecision(
                    allowed=False,
                    status_code=HTTP_FORBIDDEN,
                    reason="challenge_expired",
                )
            if not hmac.compare_digest(record.session_id, session_id):
                return HandshakeDecision(
                    allowed=False,
                    status_code=HTTP_FORBIDDEN,
                    reason="session_mismatch",
                )
            expected = self.compute_expected_response(challenge, session_id)
            if not hmac.compare_digest(expected, response):
                return HandshakeDecision(
                    allowed=False,
                    status_code=HTTP_FORBIDDEN,
                    reason="invalid_csrf_response",
                )
        finally:
            # Always burn on any exit path so the challenge cannot be retried.
            self._challenges.pop(challenge, None)

        return HandshakeDecision(allowed=True, status_code=101, reason="ok")


# ---------------------------------------------------------------------------
# Example integration shim for the `/ws/realtime` endpoint
# ---------------------------------------------------------------------------

def handle_websocket_handshake(
    guard: WebSocketOriginCSRFGuard,
    headers: Dict[str, str],
    session_id: str,
) -> HandshakeDecision:
    """Example glue code a framework handler would call before upgrading.

    `headers` should contain (case-insensitive in real frameworks; this demo
    expects already-normalized lowercase keys):
      - "origin"
      - "x-ws-csrf-challenge"
      - "x-ws-csrf-response"
    """
    return guard.authorize_handshake(
        origin=headers.get("origin"),
        session_id=session_id,
        challenge=headers.get("x-ws-csrf-challenge"),
        response=headers.get("x-ws-csrf-response"),
    )


# ---------------------------------------------------------------------------
# Self-tests
# ---------------------------------------------------------------------------

def _run_self_tests() -> None:
    secret = "super-secret-server-key"
    allowed = {"https://app.example.com"}

    # 1. Missing Origin -> 403
    guard = WebSocketOriginCSRFGuard(allowed_origins=allowed, secret=secret)
    decision = handle_websocket_handshake(guard, {}, session_id="sess-1")
    assert decision.allowed is False
    assert decision.status_code == 403
    assert decision.reason == "origin_not_allowed"

    # 2. Non-allowlisted Origin -> 403
    decision = handle_websocket_handshake(
        guard, {"origin": "https://evil.attacker.com"}, session_id="sess-1"
    )
    assert decision.allowed is False
    assert decision.status_code == 403
    assert decision.reason == "origin_not_allowed"

    # 2b. Suffix / substring bypass attempts must fail (exact match only).
    for bad_origin in (
        "https://app.example.com.evil.com",
        "https://evilapp.example.com",
        "http://app.example.com",  # scheme downgrade
        "https://app.example.com:8443",  # unexpected port not allowlisted
    ):
        decision = handle_websocket_handshake(
            guard, {"origin": bad_origin}, session_id="sess-1"
        )
        assert decision.allowed is False, f"origin should be rejected: {bad_origin}"
        assert decision.status_code == 403

    # 3. Valid Origin but no CSRF challenge -> 403
    decision = handle_websocket_handshake(
        guard, {"origin": "https://app.example.com"}, session_id="sess-1"
    )
    assert decision.allowed is False
    assert decision.status_code == 403
    assert decision.reason == "missing_csrf_challenge"

    # 4. Happy path: valid Origin + correct challenge response -> allowed
    challenge_id = guard.issue_challenge(session_id="sess-1")
    good_response = guard.compute_expected_response(challenge_id, "sess-1")
    decision = handle_websocket_handshake(
        guard,
        {
            "origin": "https://app.example.com",
            "x-ws-csrf-challenge": challenge_id,
            "x-ws-csrf-response": good_response,
        },
        session_id="sess-1",
    )
    assert decision.allowed is True
    assert decision.status_code == 101

    # 5. Replay of the same (now-consumed) challenge -> 403
    decision = handle_websocket_handshake(
        guard,
        {
            "origin": "https://app.example.com",
            "x-ws-csrf-challenge": challenge_id,
            "x-ws-csrf-response": good_response,
        },
        session_id="sess-1",
    )
    assert decision.allowed is False
    assert decision.status_code == 403
    assert decision.reason == "unknown_or_consumed_challenge"

    # 6. Forged/incorrect response value -> 403
    challenge_id2 = guard.issue_challenge(session_id="sess-1")
    decision = handle_websocket_handshake(
        guard,
        {
            "origin": "https://app.example.com",
            "x-ws-csrf-challenge": challenge_id2,
            "x-ws-csrf-response": "deadbeef" * 8,
        },
        session_id="sess-1",
    )
    assert decision.allowed is False
    assert decision.status_code == 403
    assert decision.reason == "invalid_csrf_response"

    # 7. Session mismatch (challenge minted for a different session) -> 403
    challenge_id3 = guard.issue_challenge(session_id="sess-victim")
    forged_response = guard.compute_expected_response(challenge_id3, "sess-attacker")
    decision = handle_websocket_handshake(
        guard,
        {
            "origin": "https://app.example.com",
            "x-ws-csrf-challenge": challenge_id3,
            "x-ws-csrf-response": forged_response,
        },
        session_id="sess-attacker",
    )
    assert decision.allowed is False
    assert decision.status_code == 403
    assert decision.reason == "session_mismatch"

    # 8. Expired challenge -> 403
    fixed_time = [1000.0]
    guard2 = WebSocketOriginCSRFGuard(
        allowed_origins=allowed,
        secret=secret,
        clock=lambda: fixed_time[0],
    )
    challenge_id4 = guard2.issue_challenge(session_id="sess-1")
    response4 = guard2.compute_expected_response(challenge_id4, "sess-1")
    fixed_time[0] = 1000.0 + CHALLENGE_TTL_SECONDS + 1
    decision = handle_websocket_handshake(
        guard2,
        {
            "origin": "https://app.example.com",
            "x-ws-csrf-challenge": challenge_id4,
            "x-ws-csrf-response": response4,
        },
        session_id="sess-1",
    )
    assert decision.allowed is False
    assert decision.status_code == 403
    assert decision.reason == "challenge_expired"

    print("All 8 WebSocket Origin/CSRF fix self-tests passed.")


if __name__ == "__main__":
    _run_self_tests()
